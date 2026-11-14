-- Immutable R2 payload chosen by the successful signer state transition.
-- NULL preserves the legacy e/<envelope>/s<index> layout.
ALTER TABLE sign_signers ADD COLUMN payload_key TEXT;
