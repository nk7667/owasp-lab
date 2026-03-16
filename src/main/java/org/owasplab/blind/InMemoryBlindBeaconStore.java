package org.owasplab.blind;

import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

@Component
public class InMemoryBlindBeaconStore implements BlindBeaconStore {
    private final Deque<BlindBeaconEvent> deque = new ArrayDeque<>();
    private final int capacity = 300;

    @Override
    public void append(BlindBeaconEvent event) {
        if (event == null) return;
        synchronized (deque) {
            deque.addLast(event);
            while (deque.size() > capacity) deque.removeFirst();
        }
    }

    @Override
    public List<BlindBeaconEvent> recent(Long profileId, int limit) {
        int n = limit <= 0 ? 10 : Math.min(limit, 100);
        List<BlindBeaconEvent> out = new ArrayList<>(n);
        synchronized (deque) {
            for (BlindBeaconEvent e : deque) {
                if (profileId != null && e.getProfileId() != null && !profileId.equals(e.getProfileId())) {
                    continue;
                }
                if (profileId != null && e.getProfileId() == null) continue;
                out.add(e);
            }
        }
        int size = out.size();
        if (size <= n) return out;
        return out.subList(size - n, size);
    }
}

