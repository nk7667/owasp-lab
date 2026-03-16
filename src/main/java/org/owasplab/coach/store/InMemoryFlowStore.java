package org.owasplab.coach.store;

import org.owasplab.coach.model.FlowRecord;
import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class InMemoryFlowStore implements FlowStore {
    private static class Bucket {
        final Deque<FlowRecord> dq = new ArrayDeque<>();
    }

    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final int capacityPerSession = 20;

    @Override
    public void append(FlowRecord record) {
        if (record == null) return;
        String key = record.getSessionKey();

        Bucket b = buckets.computeIfAbsent(key, k -> new Bucket());
        synchronized (b) {
            b.dq.addLast(record);
            while (b.dq.size() > capacityPerSession) {
                b.dq.removeFirst();
            }
        }
    }

    @Override
    public List<FlowRecord> recent(String sessionKey, int limit) {
        String key = (sessionKey == null || sessionKey.trim().isEmpty()) ? "anon" : sessionKey;
        Bucket b = buckets.get(key);
        if (b == null)return new ArrayList<>();

        int n =Math.max(0 ,Math.min(limit <= 0?10 :limit,capacityPerSession));
        List<FlowRecord> out =new ArrayList<>(n);
        synchronized (b){
            int i=0;
            for(java.util.Iterator<FlowRecord>it =b.dq.descendingIterator(); it.hasNext() && i<n;) {
                out.add(it.next());
                i++;
            }
        }
        return out;
    }
}


