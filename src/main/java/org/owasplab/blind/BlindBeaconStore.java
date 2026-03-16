package org.owasplab.blind;

import java.util.List;

public interface BlindBeaconStore {
    void append(BlindBeaconEvent event);
    List<BlindBeaconEvent> recent(Long profileId, int limit);
}

