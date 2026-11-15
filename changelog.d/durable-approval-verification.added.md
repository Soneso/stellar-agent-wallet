- Add read-only durable approval facts and envelope and intent verification APIs.
  Retain intent challenge subjects and distinguish revoked approval records.
  Callers constructing `ConsentPayload` set `challenge_subject` to `None`;
  `record_consent` fills the verified intent value.
