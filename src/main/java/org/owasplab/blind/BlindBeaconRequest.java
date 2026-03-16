package org.owasplab.blind;

public class BlindBeaconRequest {
    private Long profileId;
    private String kind;
    private String view;
    private String mode;
    private String payload;
    private Long ts;

    public BlindBeaconRequest() {}

    public Long getProfileId() { return profileId; }
    public void setProfileId(Long profileId) { this.profileId = profileId; }

    public String getKind() { return kind; }
    public void setKind(String kind) { this.kind = kind; }

    public String getView() { return view; }
    public void setView(String view) { this.view = view; }

    public String getMode() { return mode; }
    public void setMode(String mode) { this.mode = mode; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public Long getTs() { return ts; }
    public void setTs(Long ts) { this.ts = ts; }
}

