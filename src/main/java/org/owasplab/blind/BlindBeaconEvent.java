package org.owasplab.blind;

public class BlindBeaconEvent {
    private String id;
    private long ts;
    private String sessionKey;
    private Long profileId;
    private String kind;
    private String view;
    private String mode;
    private String payload;

    public BlindBeaconEvent() {}

    public BlindBeaconEvent(
            String id,
            long ts,
            String sessionKey,
            Long profileId,
            String kind,
            String view,
            String mode,
            String payload
    ) {
        this.id = id;
        this.ts = ts;
        this.sessionKey = sessionKey;
        this.profileId = profileId;
        this.kind = kind;
        this.view = view;
        this.mode = mode;
        this.payload = payload;
    }

    public String getId() { return id; }
    public long getTs() { return ts; }
    public String getSessionKey() { return sessionKey; }
    public Long getProfileId() { return profileId; }
    public String getKind() { return kind; }
    public String getView() { return view; }
    public String getMode() { return mode; }
    public String getPayload() { return payload; }
}

