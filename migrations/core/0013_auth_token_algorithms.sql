-- Existing clients keep ES256; approved clients can select the OIDC RS256 algorithm.
ALTER TABLE auth_clients ADD COLUMN id_token_signed_response_alg TEXT NOT NULL DEFAULT 'ES256' CHECK (id_token_signed_response_alg IN ('ES256','RS256'));
