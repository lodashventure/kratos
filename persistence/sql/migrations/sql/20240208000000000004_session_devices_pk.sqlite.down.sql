CREATE TABLE IF NOT EXISTS "_session_devices_tmp"
(
  "id"         UUID PRIMARY KEY NOT NULL,
  "ip_address" VARCHAR(50)  DEFAULT '',
  "user_agent" VARCHAR(512) DEFAULT '',
  "location"   VARCHAR(512) DEFAULT '',
  "nid"        UUID             NOT NULL,
  "session_id" UUID             NOT NULL,
  "created_at" timestamp        NOT NULL,
  "updated_at" timestamp        NOT NULL,
  CONSTRAINT "session_metadata_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "sessions" ("id") ON DELETE cascade,
  CONSTRAINT "session_metadata_nid_fk" FOREIGN KEY ("nid") REFERENCES "networks" ("id") ON DELETE cascade,
  CONSTRAINT unique_session_device UNIQUE (nid, session_id, ip_address, user_agent)
);

INSERT INTO "_session_devices_tmp"
    ("id", "ip_address", "user_agent", "location", "nid", "session_id", "created_at", "updated_at")
SELECT
    "id", "ip_address", "user_agent", "location", "nid", "session_id", "created_at", "updated_at"
FROM "session_devices";

DROP TABLE "session_devices";
ALTER TABLE "_session_devices_tmp" RENAME TO "session_devices";

CREATE INDEX "session_devices_id_nid_idx" ON "session_devices" (id, nid);
CREATE INDEX "session_devices_session_id_nid_idx" ON "session_devices" (session_id, nid);
