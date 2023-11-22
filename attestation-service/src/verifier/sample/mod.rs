use anyhow::{anyhow, Context, Result};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha384};
use kbs_types::{CombinedAttestation, TeeEvidence, CustomClaims, NestedTEE};

#[derive(Serialize, Deserialize, Debug)]
struct SampleTeeEvidence {
    svn: String,
    report_data: String,
}

#[derive(Debug, Default)]
pub struct Sample {}

#[async_trait]
impl Verifier for Sample {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &CombinedAttestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tee_evidence = serde_json::from_str::<SampleTeeEvidence>(&attestation.tee_evidence.cpu_evidence)
            .context("Deserialize Quote failed.")?;

        debug!("{}", attestation.tee_evidence.custom_claims.nested_tee.attestation_report);

        let mut hasher = Sha384::new();
        hasher.update(&attestation.tee_evidence.custom_claims.nested_tee.attestation_report);
        hasher.update(&nonce);
        let intermediate_base64 = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        
        let mut hasher_final = Sha384::new();
        hasher_final.update(&intermediate_base64);
        hasher_final.update(&attestation.tee_pubkey.k_mod);
        hasher_final.update(&attestation.tee_pubkey.k_exp);
        let reference_report_data =
            base64::engine::general_purpose::STANDARD.encode(hasher_final.finalize());

        // let mut hasher = Sha384::new();
        // hasher.update(&nonce);
        // hasher.update(&attestation.tee_pubkey.k_mod);
        // hasher.update(&attestation.tee_pubkey.k_exp);
        // let reference_report_data =
        //     base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

        verify_tee_evidence(reference_report_data, &tee_evidence)
            .await
            .context("Evidence's identity verification error.")?;

        debug!("TEE-Evidence<sample>: {:?}", tee_evidence);

        parse_tee_evidence(&tee_evidence)
    }
}

async fn verify_tee_evidence(
    reference_report_data: String,
    tee_evidence: &SampleTeeEvidence,
) -> Result<()> {
    // Verify the TEE Hardware signature. (Null for sample TEE)

    // Emulate the report data.
    if tee_evidence.report_data != reference_report_data {
        return Err(anyhow!("Report data verification failed!"));
    }

    Ok(())
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn parse_tee_evidence(quote: &SampleTeeEvidence) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "svn": quote.svn
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}
