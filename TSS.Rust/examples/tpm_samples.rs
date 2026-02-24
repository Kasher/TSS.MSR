use std::io::{self, Write};
use tss_rust::{
    auth_session::Session,
    crypto::Crypto,
    device::{TpmDevice, TpmTbsDevice}, error::TpmError,
    policy::{self, PolicyTree, PolicyCommandCode, PolicyLocality, PolicyOr, PolicyPassword},
    tpm2_impl::*, tpm_structure::{TpmEnum}, tpm_types::*
};

lazy_static::lazy_static! {
    pub static ref Aes128Cfb: TPMT_SYM_DEF_OBJECT = TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB);
}

fn set_color(color: u8) {
    if color == 0 {
        print!("\x1b[0m");
    } else {
        print!("\x1b[1;32m"); // Green
    }
}

fn print_error(msg: &str) {
    eprintln!("\x1b[1;31m{}\x1b[0m", msg);
}

fn announce(test_name: &str) {
    set_color(1);
    println!();
    println!("==============================================================================================================================");
    println!("             {}", test_name);
    println!("==============================================================================================================================");
    println!();
    io::stdout().flush().unwrap();
    set_color(0);
}

fn get_capabilities(tpm: &mut Tpm2) -> Result<(), Box<dyn std::error::Error>> {
    let mut start_val = 0;

    announce("************************* Algorithms *************************");

    // For the first example we show how to get a batch (8) properties at a time.
    // For simplicity, subsequent samples just get one at a time: avoiding the
    // nested loop.

    loop {
        let addition_to_start_val: u32;

        let caps = tpm.GetCapability(TPM_CAP::ALGS, start_val, 8)?;
        if let Some(caps) = caps.capabilityData {
            if let TPMU_CAPABILITIES::algorithms(props) = caps {
                for p in props.algProperties.iter() {
                    println!("{}: {}", p.alg, p.algProperties);
                }

                addition_to_start_val = (props.algProperties[props.algProperties.len() - 1]
                    .alg
                    .get_value()
                    + 1)
                .into();
            } else {
                break;
            }
        } else {
            break;
        }

        if (caps.moreData == 0) {
            break;
        }

        start_val += addition_to_start_val;
    }

    start_val = 0;

    let mut supported_commands: Vec<String> = Vec::new();

    loop {
        let caps = tpm.GetCapability(TPM_CAP::COMMANDS, start_val, 32)?;

        if let Some(caps) = caps.capabilityData {
            if let TPMU_CAPABILITIES::command(props) = caps {
                for p in props.commandAttributes.iter() {
                    let command_value = p.get_value() & 0xFFFF;
                    // Decode the packed structure
                    if let Ok(cc) = TPM_CC::try_from(command_value) {
                        supported_commands.push(format!("TPM_CC_{}", cc.to_string()));
                    }
                    // let masked_attr = TPMA_CC::try_from(p.get_value() & 0xFFff0000)?;

                    // println!("Command {}", cc);

                    start_val = command_value;
                }
            } else {
                break;
            }
        } else {
            break;
        }

        if (caps.moreData == 0) {
            break;
        }

        start_val += 1;
    }

    supported_commands.sort();

    let announcement = format!("TPM supports {} commands", supported_commands.len());

    announce(&announcement);
    let column_width = 35;
    let columns = 3;
    let rows = (supported_commands.len() + columns - 1) / columns;

    for row in 0..rows {
        for col in 0..columns {
            let index = row + col * rows;
            if index < supported_commands.len() {
                let cmd = &supported_commands[index];
                print!("{:<width$}", cmd, width = column_width);
            }
        }
        println!(); // Print newline after each row
    }

    Ok(())
}

fn make_storage_primary(tpm: &mut Tpm2) -> Result<TPM_HANDLE, TpmError> {
    let object_attributes = TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;
    
    let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(&Aes128Cfb, &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())), 2048, 65537));

    let unique = TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default());

    let storage_primary_template = TPMT_PUBLIC::new(TPM_ALG_ID::SHA1,
                    object_attributes,
                    &Vec::new(),           // No policy
                    &Some(parameters),
                    &Some(unique));

    let resp = tpm.CreatePrimary(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
    &TPMS_SENSITIVE_CREATE::default(),
    &storage_primary_template,
       &Default::default(),
       &Default::default())?;

    Ok(resp.handle)
}

fn make_child_signing_key(tpm: &mut Tpm2, parent: &TPM_HANDLE, restricted: bool) -> Result<TPM_HANDLE, TpmError>
{
    let restricted_attribute: TPMA_OBJECT = if restricted { TPMA_OBJECT::restricted } else { TPMA_OBJECT(0) };

    let object_attributes = TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth | restricted_attribute;

    let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(&Default::default(), 
        &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA { hashAlg: TPM_ALG_ID::SHA1 })), 2048, 65537)); // PKCS1.5

    let unique = TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default());

    let template = TPMT_PUBLIC::new(TPM_ALG_ID::SHA1, object_attributes, &Default::default(), &Some(parameters), &Some(unique));

    let new_signing_key = tpm.Create(&parent, &Default::default(), &template, &Default::default(), &Default::default())?;

    tpm.Load(&parent, &new_signing_key.outPrivate, &new_signing_key.outPublic)
}

fn make_endorsement_key(tpm: &mut Tpm2) -> Result<TPM_HANDLE, TpmError> {
    let object_attributes = TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
    | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
    | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;

    let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(&Aes128Cfb, &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())), 2048, 65537));

    let unique = TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default());

    let template = TPMT_PUBLIC::new(TPM_ALG_ID::SHA1,
                    object_attributes,
                    &Vec::new(),
                    &Some(parameters),
                    &Some(unique));

    let resp = tpm.CreatePrimary(&TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()),
        &TPMS_SENSITIVE_CREATE::default(),
        &template,
        &Default::default(),
        &Default::default())?;
    
    Ok(resp.handle)
}

fn attestation(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Attestation Sample");

    // Attestation is the TPM signing internal data structures. The TPM can perform
    // several-types of attestation: we demonstrate signing PCR, keys, and time.

    // To get attestation information we need a restricted signing key and privacy authorization.
    let primary_key = make_storage_primary(tpm)?;
    let sig_key = make_child_signing_key(tpm, &primary_key, true)?;

    let nonce = vec![2, 6, 1, 1, 9];

    println!(">> PCR Quoting");
    println!("Created and loaded signing key with handle: {:?}", sig_key);
    
    // Set up PCR selection for the quote
    let pcrs_to_quote = TPMS_PCR_SELECTION::get_selection_array(
        TPM_ALG_ID::SHA1, 7 );

    // Do an event to make sure the value is non-zero
    tpm.PCR_Event(&TPM_HANDLE::pcr(7), &vec![1, 2, 3])?;

    // Then read the value so that we can validate the signature later
    let pcr_vals = tpm.PCR_Read(&pcrs_to_quote)?;
    println!("Read {} PCR values for quoting", pcr_vals.pcrValues.len());

    // Do the quote.  Note that we provide a nonce.
    let quote = tpm.Quote(&sig_key, &nonce, &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?, &pcrs_to_quote)?;
    
    // Need to cast to the proper attestation type to validate
    let attested = quote.quoted.attested;
    
    if let Some(TPMU_ATTEST::quote(quote_attest)) = attested {
        println!("PCR Quote obtained successfully");
        println!("PCR Quote: {:?}", quote_attest);
        println!("Nonce: {:?}", quote.quoted.extraData);
    } else {
        println!("Failed to cast to quote attestation");
        return Err(TpmError::InvalidParameter);
    } ;

    let time_nonce: Vec<u8> = vec![1, 6, 8, 2, 1];
    println!(">> Time Quoting, using nonce {:?}", time_nonce);

    let time_quote = tpm.GetTime(&TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()), &sig_key, &time_nonce, &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?)?;

    if let Some(TPMU_ATTEST::time(time_attest)) = time_quote.timeInfo.attested {
        println!("Time Quote obtained successfully");
        let clock_info = time_attest.time.clockInfo;
        println!(" Firmware Version: {}", time_attest.firmwareVersion);
        println!(" Time: {}", time_attest.time.time);
        println!(" Clock: {}", clock_info.clock);
        println!(" ResetCount: {}", clock_info.resetCount);
        println!(" RestartCount: {}", clock_info.restartCount);
        println!(" Nonce: {:?}", time_quote.timeInfo.extraData);
    } else {
        println!("Failed to cast to quote attestation");
        return Err(TpmError::InvalidParameter);
    } ;

    // Get a key attestation.  For simplicity we have the signingKey self-certify b
    let key_nonce: Vec<u8> = vec![0, 9, 1, 1, 2, 3];
    println!(">> Key Quoting, using nonce {:?}", key_nonce);

    let key_quote = tpm.Certify(&sig_key, &sig_key, &key_nonce, &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?)?;

    if let Some(TPMU_ATTEST::certify(certify_attest)) = &key_quote.certifyInfo.attested {
        println!("Key certification obtained successfully");
        println!(" Name of certified key: {:?}", certify_attest.name);
        println!(" Qualified name of certified key: {:?}", certify_attest.qualifiedName);
        println!(" nonce: {:?}", &key_quote.certifyInfo.extraData);
        println!(" Signature: {:?}", &key_quote.signature);
    } else {
        println!("Failed to cast to quote attestation");
        return Err(TpmError::InvalidParameter);
    } ;

    let pub_key = tpm.ReadPublic(&sig_key)?;

    if (pub_key.outPublic.validate_certify(&pub_key.outPublic, &key_nonce, &key_quote)?) {
        println!("Key certification signature verification SUCCESSFUL! ");
    } else {
        println!("Key certification signature verification FAILED! ");
    }

    // // Clean up - flush keys from TPM
    tpm.FlushContext(&sig_key)?;
    println!("Cleaned up keys from TPM");

    Ok(())
}


fn activate_credentials(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Activate Credentials");

    // Make a new EK and get the public key
    let ek_handle = make_endorsement_key(tpm)?;
    let ek_pub_response = tpm.ReadPublic(&ek_handle)?;
    let ek_pub = ek_pub_response.outPublic;

    // Make another key that we will "activate"
    let srk = make_storage_primary(tpm)?;
    let key_to_activate = make_child_signing_key(tpm, &srk, true)?;
    tpm.FlushContext(&srk)?;

    // Make a secret using the TSS.Rust RNG
    let secret = Crypto::get_random(20);
    let name_of_key_to_activate = key_to_activate.get_name()?;

    // Use TSS.Rust to get an activation blob
    let cred = ek_pub.create_activation(&secret, &name_of_key_to_activate)?;
    let recovered_secret = tpm.ActivateCredential(&key_to_activate, &ek_handle, 
                                                     &cred.credential_blob, &cred.secret)?;

    println!("Secret:                         {:?}", secret);
    println!("Secret recovered from Activate: {:?}", recovered_secret);

    if secret != recovered_secret {
        print_error("Secret mismatch when using TSS.Rust to create an activation credential (known create_activation issue)");
    } else {
        println!("TSS.Rust-created activation blob verified");
    }

    // You can also use the TPM to make the activation credential
    let tpm_activator = tpm.MakeCredential(&ek_handle, &secret, &name_of_key_to_activate)?;

    let recovered_secret = tpm.ActivateCredential(&key_to_activate, &ek_handle,
                                             &tpm_activator.credentialBlob, &tpm_activator.secret)?;

    println!("TPM-created activation blob: Secret recovered from Activate: {:?}", recovered_secret);
    
    assert!(secret == recovered_secret, "Secret mismatch when using the TPM to create an activation credential");

    tpm.FlushContext(&ek_handle)?;
    tpm.FlushContext(&key_to_activate)?;

    Ok(())
}

// =============================== Basic Samples (no auth sessions needed) ===============================

fn rand_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Random Number Sample");

    // Get 20 random bytes from the TPM
    let rand = tpm.GetRandom(20)?;
    println!("Random bytes (first call): {:?}", rand);

    // Add entropy to the TPM RNG
    tpm.StirRandom(&vec![1, 2, 3, 4, 5])?;
    println!("Stirred random with [1, 2, 3, 4, 5]");

    // Get more random bytes
    let rand2 = tpm.GetRandom(20)?;
    println!("Random bytes (second call): {:?}", rand2);

    assert_ne!(rand, rand2, "Two random calls should produce different results");
    println!("Random number generation works correctly");

    Ok(())
}

fn hash_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Hash Sample");

    let data = b"Hello, TPM hashing!".to_vec();

    // Simple hash
    let hash_resp = tpm.Hash(&data, TPM_ALG_ID::SHA256, &TPM_HANDLE::new(TPM_RH::NULL.get_value()))?;
    println!("SHA-256 hash of data: {:?}", hash_resp.outHash);

    // Hash with SHA-1
    let hash1_resp = tpm.Hash(&data, TPM_ALG_ID::SHA1, &TPM_HANDLE::new(TPM_RH::NULL.get_value()))?;
    println!("SHA-1 hash of data:   {:?}", hash1_resp.outHash);

    // Hash sequence (multi-part hashing)
    println!("\n>> Hash Sequence (multi-part hashing)");
    let accumulator = b"Hello, TPM hashing!".to_vec();
    let part1 = accumulator[..10].to_vec();
    let part2 = accumulator[10..].to_vec();

    let seq_handle = tpm.HashSequenceStart(&vec![], TPM_ALG_ID::SHA256)?;
    tpm.SequenceUpdate(&seq_handle, &part1)?;
    let seq_result = tpm.SequenceComplete(&seq_handle, &part2, &TPM_HANDLE::new(TPM_RH::NULL.get_value()))?;

    println!("Sequence hash result:  {:?}", seq_result.result);
    assert_eq!(hash_resp.outHash, seq_result.result,
        "Single-shot and sequence hash should match");
    println!("Single-shot and sequence hash results match!");

    Ok(())
}

fn hmac_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("HMAC Sample");

    // Create an HMAC primary key
    let object_attributes = TPMA_OBJECT::sign
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;

    let parameters = TPMU_PUBLIC_PARMS::keyedHashDetail(TPMS_KEYEDHASH_PARMS::new(
        &Some(TPMU_SCHEME_KEYEDHASH::hmac(TPMS_SCHEME_HMAC { hashAlg: TPM_ALG_ID::SHA256 }))));

    let unique = TPMU_PUBLIC_ID::keyedHash(TPM2B_DIGEST_KEYEDHASH::default());

    let hmac_template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA256,
        object_attributes,
        &Vec::new(),
        &Some(parameters),
        &Some(unique),
    );

    let hmac_key_resp = tpm.CreatePrimary(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &TPMS_SENSITIVE_CREATE::default(),
        &hmac_template,
        &Default::default(),
        &Default::default(),
    )?;

    println!("Created HMAC key with handle: {:?}", hmac_key_resp.handle);

    // HMAC using sequence interface
    let data = b"Data to HMAC".to_vec();
    let hmac_handle = tpm.HMAC_Start(&hmac_key_resp.handle, &vec![], TPM_ALG_ID::SHA256)?;
    tpm.SequenceUpdate(&hmac_handle, &data)?;
    let hmac_result = tpm.SequenceComplete(&hmac_handle, &vec![], &TPM_HANDLE::new(TPM_RH::NULL.get_value()))?;
    println!("HMAC (sequence):   {:?}", hmac_result.result);

    // HMAC using direct command
    let hmac_direct = tpm.HMAC(&hmac_key_resp.handle, &data, TPM_ALG_ID::SHA256)?;
    println!("HMAC (direct):     {:?}", hmac_direct);

    assert_eq!(hmac_result.result, hmac_direct, "Sequence and direct HMAC should match");
    println!("Sequence and direct HMAC results match!");

    tpm.FlushContext(&hmac_key_resp.handle)?;
    Ok(())
}

fn pcr_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PCR Sample");

    // Use PCR 16 (resettable)
    let pcr_handle = TPM_HANDLE::pcr(16);

    // Reset the PCR first
    tpm.PCR_Reset(&pcr_handle)?;
    println!("PCR 16 reset");

    // Read the PCR value (should be all zeros after reset)
    let pcr_selection = TPMS_PCR_SELECTION::get_selection_array(TPM_ALG_ID::SHA256, 16);
    let pcr_vals = tpm.PCR_Read(&pcr_selection)?;
    println!("PCR 16 after reset: {:?}", pcr_vals.pcrValues);

    // Extend a value into the PCR
    let event_data = vec![1, 2, 3, 4, 5];
    tpm.PCR_Event(&pcr_handle, &event_data)?;
    println!("Extended event data [1, 2, 3, 4, 5] into PCR 16");

    // Read the PCR value after extend
    let pcr_vals2 = tpm.PCR_Read(&pcr_selection)?;
    println!("PCR 16 after event: {:?}", pcr_vals2.pcrValues);

    // Extend with a hash value
    let extend_hash = TPMT_HA::new(TPM_ALG_ID::SHA256, &Crypto::hash(TPM_ALG_ID::SHA256, &vec![6, 7, 8])?);
    tpm.PCR_Extend(&pcr_handle, &vec![extend_hash])?;
    println!("Extended hash into PCR 16");

    // Read again
    let pcr_vals3 = tpm.PCR_Read(&pcr_selection)?;
    println!("PCR 16 after extend: {:?}", pcr_vals3.pcrValues);

    // Reset again
    tpm.PCR_Reset(&pcr_handle)?;
    let pcr_vals_final = tpm.PCR_Read(&pcr_selection)?;
    println!("PCR 16 after final reset: {:?}", pcr_vals_final.pcrValues);

    println!("PCR operations completed successfully");
    Ok(())
}

fn primary_keys_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Primary Keys Sample");

    // Create an RSA signing primary key
    let sign_attrs = TPMA_OBJECT::sign
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;

    let sign_parms = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
        &Default::default(),
        &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA { hashAlg: TPM_ALG_ID::SHA256 })),
        2048, 65537,
    ));

    let sign_template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA256,
        sign_attrs,
        &Vec::new(),
        &Some(sign_parms),
        &Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    );

    let new_primary = tpm.CreatePrimary(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &TPMS_SENSITIVE_CREATE::default(),
        &sign_template,
        &Default::default(),
        &Default::default(),
    )?;
    println!("Created signing primary key with handle: {:?}", new_primary.handle);

    // Sign some data
    let data_to_sign = Crypto::hash(TPM_ALG_ID::SHA256, &b"Data to sign".to_vec())?;
    let signature = tpm.Sign(
        &new_primary.handle,
        &data_to_sign,
        &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?,
        &TPMT_TK_HASHCHECK::default(),
    )?;
    println!("Data signed successfully, signature: {:?}", signature.is_some());

    // Persist the key with EvictControl
    let persistent_handle = TPM_HANDLE::new(0x81000100);
    
    // First clean up any existing persistent key at this handle
    tpm.allow_errors();
    let _ = tpm.EvictControl(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &persistent_handle,
        &persistent_handle,
    );

    tpm.EvictControl(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &new_primary.handle,
        &persistent_handle,
    )?;
    println!("Key persisted at handle: {:?}", persistent_handle);

    // Read back the public part from the persistent handle
    let pub_data = tpm.ReadPublic(&persistent_handle)?;
    println!("Read back public data from persistent handle");
    println!("Algorithm: {:?}", pub_data.outPublic.nameAlg);

    // Clean up - remove persistent key
    tpm.EvictControl(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &persistent_handle,
        &persistent_handle,
    )?;
    println!("Removed persistent key");

    tpm.FlushContext(&new_primary.handle)?;
    println!("Primary keys sample completed successfully");
    Ok(())
}

fn child_keys_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Child Keys Sample");

    // Create a storage primary (parent key)
    let primary = make_storage_primary(tpm)?;
    println!("Created storage primary: {:?}", primary);

    // Create a child signing key
    let sign_key = make_child_signing_key(tpm, &primary, false)?;
    println!("Created child signing key: {:?}", sign_key);

    // Sign some data
    let data_to_sign = Crypto::hash(TPM_ALG_ID::SHA1, &b"Test data for signing".to_vec())?;
    let signature = tpm.Sign(
        &sign_key,
        &data_to_sign,
        &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?,
        &TPMT_TK_HASHCHECK::default(),
    )?;
    assert!(signature.is_some(), "Signature should not be empty");
    println!("Signed data with child key");

    // Context save and load
    // Note: ContextSave/ContextLoad may be blocked by Windows TBS
    println!("\n>> Context Save/Load");
    let saved_context = tpm.ContextSave(&sign_key)?;
    println!("Saved signing key context");

    tpm.FlushContext(&sign_key)?;
    println!("Flushed signing key from TPM");

    let restored_key = tpm.ContextLoad(&saved_context)?;
    println!("Restored signing key from saved context: {:?}", restored_key);

    // Sign again with restored key to verify it works
    let signature2 = tpm.Sign(
        &restored_key,
        &data_to_sign,
        &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?,
        &TPMT_TK_HASHCHECK::default(),
    )?;
    assert!(signature2.is_some(), "Restored key signature should not be empty");
    println!("Signed data with restored key");

    tpm.FlushContext(&restored_key)?;
    tpm.FlushContext(&primary)?;
    println!("Child keys sample completed successfully");
    Ok(())
}

fn counter_timer_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Counter/Timer Sample");

    let time_info = tpm.ReadClock()?;
    println!("TPM Clock Information:");
    println!("Time (ms since last reset): {}", time_info.time);
    println!("Clock (ms total):           {}", time_info.clockInfo.clock);
    println!("Reset count:                {}", time_info.clockInfo.resetCount);
    println!("Restart count:              {}", time_info.clockInfo.restartCount);
    println!("Safe:                       {}", time_info.clockInfo.safe);

    println!("Counter/Timer sample completed successfully");
    Ok(())
}

fn nv_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("NV (Non-Volatile) Storage Sample");

    let owner = TPM_HANDLE::new(TPM_RH::OWNER.get_value());

    // ---- Simple NV (ordinary data) ----
    println!(">> Simple NV (read/write bytes)");
    let nv_index = TPM_HANDLE::new(0x01500100);
    let nv_data_size: u16 = 32;

    // Clean up any existing NV index
    tpm.allow_errors();
    let _ = tpm.NV_UndefineSpace(&owner, &nv_index);

    // Define the NV space
    let nv_pub = TPMS_NV_PUBLIC::new(
        &nv_index,
        TPM_ALG_ID::SHA256,
        TPMA_NV::AUTHREAD | TPMA_NV::AUTHWRITE,
        &Vec::new(),
        nv_data_size,
    );
    tpm.NV_DefineSpace(&owner, &vec![], &nv_pub)?;
    println!("Defined NV index at {:?}, size = {}", nv_index, nv_data_size);

    // Write data
    let write_data: Vec<u8> = (0..nv_data_size as u8).collect();
    tpm.NV_Write(&nv_index, &nv_index, &write_data, 0)?;
    println!("Wrote {} bytes to NV", write_data.len());

    // Read it back
    let read_data = tpm.NV_Read(&nv_index, &nv_index, nv_data_size, 0)?;
    println!("Read back: {:?}", read_data);
    assert_eq!(write_data, read_data, "NV read should match write");
    println!("NV read matches write");

    // Read public info
    let nv_pub_info = tpm.NV_ReadPublic(&nv_index)?;
    println!("NV Public info - dataSize: {}, nameAlg: {:?}", nv_pub_info.nvPublic.dataSize, nv_pub_info.nvPublic.nameAlg);

    // Clean up
    tpm.NV_UndefineSpace(&owner, &nv_index)?;
    println!("Undefined NV space");

    // ---- Counter NV ----
    println!("\n>> Counter NV");
    let counter_index = TPM_HANDLE::new(0x01500101);

    tpm.allow_errors();
    let _ = tpm.NV_UndefineSpace(&owner, &counter_index);

    let counter_pub = TPMS_NV_PUBLIC::new(
        &counter_index,
        TPM_ALG_ID::SHA256,
        TPMA_NV::AUTHREAD | TPMA_NV::AUTHWRITE | TPMA_NV::COUNTER,
        &Vec::new(),
        8,
    );
    tpm.NV_DefineSpace(&owner, &vec![], &counter_pub)?;
    println!("Defined counter NV index");

    // Increment
    tpm.NV_Increment(&counter_index, &counter_index)?;
    let counter_val = tpm.NV_Read(&counter_index, &counter_index, 8, 0)?;
    println!("Counter after first increment: {:?}", counter_val);

    tpm.NV_Increment(&counter_index, &counter_index)?;
    let counter_val2 = tpm.NV_Read(&counter_index, &counter_index, 8, 0)?;
    println!("Counter after second increment: {:?}", counter_val2);

    tpm.NV_UndefineSpace(&owner, &counter_index)?;
    println!("Counter NV works correctly");

    // ---- Bit field NV ----
    println!("\n>> Bit Field NV");
    let bit_index = TPM_HANDLE::new(0x01500102);

    tpm.allow_errors();
    let _ = tpm.NV_UndefineSpace(&owner, &bit_index);

    let bits_pub = TPMS_NV_PUBLIC::new(
        &bit_index,
        TPM_ALG_ID::SHA256,
        TPMA_NV::AUTHREAD | TPMA_NV::AUTHWRITE | TPMA_NV::BITS,
        &Vec::new(),
        8,
    );
    tpm.NV_DefineSpace(&owner, &vec![], &bits_pub)?;
    println!("Defined bit field NV index");

    tpm.NV_SetBits(&bit_index, &bit_index, 0x0000_0001)?;
    let bits_val = tpm.NV_Read(&bit_index, &bit_index, 8, 0)?;
    println!("Bits after setting bit 0: {:?}", bits_val);

    tpm.NV_SetBits(&bit_index, &bit_index, 0x0000_0004)?;
    let bits_val2 = tpm.NV_Read(&bit_index, &bit_index, 8, 0)?;
    println!("Bits after setting bit 2: {:?}", bits_val2);

    tpm.NV_UndefineSpace(&owner, &bit_index)?;
    println!("Bit field NV works correctly");

    // ---- Extend NV ----
    println!("\n>> Extend NV");
    let extend_index = TPM_HANDLE::new(0x01500103);

    tpm.allow_errors();
    let _ = tpm.NV_UndefineSpace(&owner, &extend_index);

    let extend_pub = TPMS_NV_PUBLIC::new(
        &extend_index,
        TPM_ALG_ID::SHA256,
        TPMA_NV::AUTHREAD | TPMA_NV::AUTHWRITE | TPMA_NV::EXTEND,
        &Vec::new(),
        32, // SHA-256 digest size
    );
    tpm.NV_DefineSpace(&owner, &vec![], &extend_pub)?;
    println!("Defined extend NV index");

    tpm.NV_Extend(&extend_index, &extend_index, &vec![1, 2, 3, 4, 5])?;
    let extend_val = tpm.NV_Read(&extend_index, &extend_index, 32, 0)?;
    println!("Extend NV after extend: {:?}", extend_val);

    tpm.NV_UndefineSpace(&owner, &extend_index)?;
    println!("Extend NV works correctly");

    Ok(())
}

fn rsa_encrypt_decrypt_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("RSA Encrypt/Decrypt Sample");

    // Create an RSA decryption key (not restricted - for general encrypt/decrypt)
    let rsa_attrs = TPMA_OBJECT::decrypt
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;

    let rsa_parms = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
        &Default::default(),
        &Some(TPMU_ASYM_SCHEME::oaep(TPMS_ENC_SCHEME_OAEP { hashAlg: TPM_ALG_ID::SHA256 })),
        2048, 65537,
    ));

    let rsa_template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA256,
        rsa_attrs,
        &Vec::new(),
        &Some(rsa_parms),
        &Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    );

    let key_resp = tpm.CreatePrimary(
        &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        &TPMS_SENSITIVE_CREATE::default(),
        &rsa_template,
        &Default::default(),
        &Default::default(),
    )?;
    println!("Created RSA decryption key: {:?}", key_resp.handle);

    // Encrypt data using the TPM
    let plaintext = b"Secret message for RSA encryption!".to_vec();
    let null_scheme = TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default());
    let ciphertext = tpm.RSA_Encrypt(&key_resp.handle, &plaintext, &Some(null_scheme.clone()), &vec![])?;
    println!("Encrypted {} bytes -> {} bytes ciphertext", plaintext.len(), ciphertext.len());

    // Decrypt
    let decrypted = tpm.RSA_Decrypt(&key_resp.handle, &ciphertext, &Some(null_scheme), &vec![])?;
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    assert_eq!(plaintext, decrypted, "Decrypted data should match original");
    println!("RSA encrypt/decrypt works correctly");

    tpm.FlushContext(&key_resp.handle)?;
    Ok(())
}

fn encrypt_decrypt_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Symmetric Encrypt/Decrypt Sample");

    // Create a storage primary
    let primary = make_storage_primary(tpm)?;

    // Create an AES symmetric key
    let aes_attrs = TPMA_OBJECT::decrypt | TPMA_OBJECT::sign
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;

    let aes_parms = TPMU_PUBLIC_PARMS::symDetail(TPMS_SYMCIPHER_PARMS::new(&Aes128Cfb));

    let aes_template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA256,
        aes_attrs,
        &Vec::new(),
        &Some(aes_parms),
        &Some(TPMU_PUBLIC_ID::sym(TPM2B_DIGEST_SYMCIPHER::default())),
    );

    let aes_key = tpm.Create(
        &primary,
        &TPMS_SENSITIVE_CREATE::default(),
        &aes_template,
        &Default::default(),
        &Default::default(),
    )?;
    let aes_handle = tpm.Load(&primary, &aes_key.outPrivate, &aes_key.outPublic)?;
    println!("Created and loaded AES key: {:?}", aes_handle);

    // Note: EncryptDecrypt/EncryptDecrypt2 may be blocked by Windows TBS
    let plaintext = b"Hello AES encryption!   padding!!".to_vec(); // 32 bytes (block-aligned)
    let iv = vec![0u8; 16];
    let encrypted = tpm.EncryptDecrypt(&aes_handle, 0, TPM_ALG_ID::CFB, &iv, &plaintext)?;
    println!("Encrypted {} bytes", plaintext.len());

    // Decrypt (decrypt=1)
    let decrypted = tpm.EncryptDecrypt(&aes_handle, 1, TPM_ALG_ID::CFB, &iv, &encrypted.outData)?;
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted.outData));

    assert_eq!(plaintext, decrypted.outData, "Decrypted data should match original");
    println!("AES encrypt/decrypt works correctly");

    tpm.FlushContext(&aes_handle)?;
    tpm.FlushContext(&primary)?;
    Ok(())
}

// =============================== Auth Session Samples ===============================

/// Helper: create an HMAC primary key with a policy digest and optional auth value.
/// Mirrors C++ MakeHmacPrimaryWithPolicy.
fn make_hmac_primary_with_policy(
    tpm: &mut Tpm2,
    policy_digest: &[u8],
    use_auth: &[u8],
    hash_alg: TPM_ALG_ID,
) -> Result<TPM_HANDLE, TpmError> {
    let key_data = vec![5, 4, 3, 2, 1, 0];
    let mut attrs = TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM;
    if !use_auth.is_empty() {
        attrs = attrs | TPMA_OBJECT::userWithAuth;
    }

    let parameters = TPMU_PUBLIC_PARMS::keyedHashDetail(TPMS_KEYEDHASH_PARMS::new(
        &Some(TPMU_SCHEME_KEYEDHASH::hmac(TPMS_SCHEME_HMAC { hashAlg: hash_alg }))));
    let unique = TPMU_PUBLIC_ID::keyedHash(TPM2B_DIGEST_KEYEDHASH::default());

    let templ = TPMT_PUBLIC::new(
        hash_alg, attrs, &policy_digest.to_vec(),
        &Some(parameters), &Some(unique),
    );

    let sens = TPMS_SENSITIVE_CREATE::new(&use_auth.to_vec(), &key_data);
    let resp = tpm.CreatePrimary(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &sens, &templ, &Default::default(), &Default::default(),
    )?;
    Ok(resp.handle)
}

/// Helper: get the session handle from a Session (for policy commands and FlushContext).
fn session_handle(sess: &Session) -> TPM_HANDLE {
    sess.sess_in.sessionHandle.clone()
}

fn auth_sessions_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Auth Sessions Sample");

    // Start a simple HMAC authorization session (no salt, no encryption, no bound-object)
    let mut sess = tpm.start_auth_session(TPM_SE::HMAC, TPM_ALG_ID::SHA1)?;
    println!("Started HMAC auth session: {:?}", session_handle(&sess));

    // Create a storage primary
    let primary = make_storage_primary(tpm)?;

    // Create a child key template
    let child_attrs = TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;
    let child_parms = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
        &Default::default(),
        &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA { hashAlg: TPM_ALG_ID::SHA1 })),
        2048, 65537,
    ));
    let child_template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA1, child_attrs, &Default::default(),
        &Some(child_parms),
        &Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    );

    // Create child key using the HMAC session (parent handle uses auth)
    let new_key = tpm.with_session(sess.clone()).Create(
        &primary, &Default::default(), &child_template,
        &Default::default(), &Default::default(),
    )?;
    // Retrieve updated session (nonces rolled by TPM)
    sess = tpm.last_session().unwrap();
    println!("Created child key with HMAC session");

    // Load the child key with the same session
    let loaded_key = tpm.with_session(sess.clone()).Load(
        &primary, &new_key.outPrivate, &new_key.outPublic,
    )?;
    sess = tpm.last_session().unwrap();
    println!("Loaded child key with HMAC session: {:?}", loaded_key);

    // Sign data with the loaded key using the session
    let data_to_sign = Crypto::hash(TPM_ALG_ID::SHA1, &b"Auth session test data".to_vec())?;
    let sig = tpm.with_session(sess.clone()).Sign(
        &loaded_key, &data_to_sign,
        &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?,
        &TPMT_TK_HASHCHECK::default(),
    )?;
    assert!(sig.is_some(), "HMAC session signature should not be empty");
    sess = tpm.last_session().unwrap();
    println!("Signed data using HMAC session");

    // Clean up
    tpm.FlushContext(&session_handle(&sess))?;
    tpm.FlushContext(&loaded_key)?;
    tpm.FlushContext(&primary)?;

    println!("Auth sessions sample completed successfully");
    Ok(())
}

fn dictionary_attack_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Dictionary Attack Sample");

    // Reset the lockout counter
    let lockout = TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value());
    tpm.DictionaryAttackLockReset(&lockout)?;
    println!("Dictionary attack lockout reset");

    // Configure dictionary attack parameters
    let new_max_tries: u32 = 1000;
    let new_recovery_time: u32 = 1;
    let lockout_recovery: u32 = 1;
    tpm.DictionaryAttackParameters(&lockout, new_max_tries, new_recovery_time, lockout_recovery)?;
    println!("Set DA parameters: maxTries={}, recoveryTime={}, lockoutRecovery={}",
             new_max_tries, new_recovery_time, lockout_recovery);

    println!("Dictionary attack sample completed successfully");
    Ok(())
}

fn misc_admin_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Misc Admin Sample");

    // Self Testing
    println!(">> Self Testing");
    tpm.allow_errors();
    let _ = tpm.SelfTest(1);
    println!("SelfTest completed (or was already done)");

    let test_result = tpm.GetTestResult()?;
    println!("GetTestResult: {} bytes of data, rc={}", test_result.outData.len(), test_result.testResult);

    let to_be_tested = tpm.IncrementalSelfTest(&vec![TPM_ALG_ID::SHA1, TPM_ALG_ID::AES])?;
    println!("IncrementalSelfTest: {} algorithms still to test", to_be_tested.len());

    // Clock Management
    println!("\n>> Clock Management");
    let start_clock = tpm.ReadClock()?;
    println!("Start clock: {}", start_clock.clockInfo.clock);

    let dt: u64 = 10_000_000;
    let new_clock = start_clock.clockInfo.clock + dt;
    tpm.ClockSet(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), new_clock)?;

    let now_clock = tpm.ReadClock()?;
    let dt_actual = now_clock.clockInfo.clock - start_clock.clockInfo.clock;
    println!("Clock advanced by: {} (requested {})", dt_actual, dt);

    // Can't set clock backwards
    tpm.allow_errors();
    let _ = tpm.ClockSet(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), start_clock.clockInfo.clock);
    println!("Setting clock backwards: last_rc = {}", tpm.last_response_code());

    // Adjust clock rate
    tpm.ClockRateAdjust(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), TPM_CLOCK_ADJUST::MEDIUM_SLOWER)?;
    tpm.ClockRateAdjust(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), TPM_CLOCK_ADJUST::MEDIUM_FASTER)?;
    println!("Clock rate adjusted (slower, then faster)");

    println!("Misc admin sample completed successfully");
    Ok(())
}

fn policy_simplest_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Policy Simplest Sample (PolicyCommandCode)");

    // Use a trial session to compute the policy digest for PolicyCommandCode(HMAC_Start)
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA1)?;
    tpm.PolicyCommandCode(&session_handle(&trial), TPM_CC::HMAC_Start)?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("Computed policy digest (trial): {:?}", policy_digest);

    // Create an HMAC primary with this policy (no userAuth)
    let hmac_key = make_hmac_primary_with_policy(tpm, &policy_digest, &[], TPM_ALG_ID::SHA1)?;
    println!("Created HMAC key with PolicyCommandCode policy");

    // Show that plain authValue-based access fails
    tpm.allow_errors();
    let _ = tpm.HMAC_Start(&hmac_key, &vec![], TPM_ALG_ID::SHA1);
    println!("Plain auth HMAC_Start: last_rc = {} (expected AUTH_UNAVAILABLE)", tpm.last_response_code());

    // Use a real policy session
    let sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA1)?;
    tpm.PolicyCommandCode(&session_handle(&sess), TPM_CC::HMAC_Start)?;

    // Verify the policy digest matches
    let digest = tpm.PolicyGetDigest(&session_handle(&sess))?;
    println!("Computed policy digest (real): {:?}", digest);
    assert_eq!(policy_digest, digest, "Trial and real policy digests should match");

    // Execute the authorized command - should succeed
    let hmac_seq_handle = tpm.with_session(sess.clone()).HMAC_Start(&hmac_key, &vec![], TPM_ALG_ID::SHA1)?;
    println!("Policy-authorized HMAC_Start succeeded: {:?}", hmac_seq_handle);
    tpm.FlushContext(&hmac_seq_handle)?;
    tpm.FlushContext(&session_handle(&sess))?;

    // Try a different command with the same policy - should fail with POLICY_CC
    let sess2 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA1)?;
    tpm.PolicyCommandCode(&session_handle(&sess2), TPM_CC::HMAC_Start)?;

    tpm.allow_errors();
    let _ = tpm.with_session(sess2.clone()).Unseal(&hmac_key);
    println!("Unseal with HMAC_Start policy: last_rc = {} (expected POLICY_CC)", tpm.last_response_code());

    tpm.FlushContext(&session_handle(&sess2))?;
    tpm.FlushContext(&hmac_key)?;

    println!("Policy simplest sample completed successfully");
    Ok(())
}

fn unseal_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Unseal Sample");

    // Reset dictionary attack lockout (may fail on some TPMs)
    tpm.allow_errors();
    let _ = tpm.DictionaryAttackLockReset(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()));
    if tpm.last_response_code() != TPM_RC::SUCCESS {
        println!("Note: DictionaryAttackLockReset failed (rc={}), continuing...", tpm.last_response_code());
    }

    let pcr: u32 = 15;
    let bank = TPM_ALG_ID::SHA256;

    // Set the PCR to a known value
    tpm.PCR_Event(&TPM_HANDLE::pcr(pcr), &vec![1, 2, 3, 4])?;

    // Read the current PCR value
    let pcr_selection = TPMS_PCR_SELECTION::get_selection_array(bank, pcr);
    let pcr_vals = tpm.PCR_Read(&pcr_selection)?;
    println!("PCR {} value: {:?}", pcr, pcr_vals.pcrValues);

    // Compute policy digest: PolicyPCR + PolicyPassword
    // Use a trial session to compute the digest
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;

    // Compute the PCR digest (hash of selected PCR values)
    let mut pcr_digest_data = Vec::new();
    for v in &pcr_vals.pcrValues {
        pcr_digest_data.extend_from_slice(&v.buffer);
    }
    let pcr_digest = Crypto::hash(bank, &pcr_digest_data)?;

    tpm.PolicyPCR(&session_handle(&trial), &pcr_digest, &pcr_selection)?;
    tpm.PolicyPassword(&session_handle(&trial))?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("Policy digest (PCR + Password): {:?}", policy_digest);

    // Create a sealed object under a storage primary
    let primary = make_storage_primary(tpm)?;

    let seal_attrs = TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM;
    let seal_parms = TPMU_PUBLIC_PARMS::keyedHashDetail(
        TPMS_KEYEDHASH_PARMS::new(&Some(TPMU_SCHEME_KEYEDHASH::null(TPMS_NULL_SCHEME_KEYEDHASH::default()))));
    let seal_template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA256, seal_attrs, &policy_digest,
        &Some(seal_parms),
        &Some(TPMU_PUBLIC_ID::keyedHash(TPM2B_DIGEST_KEYEDHASH::default())),
    );

    let data_to_seal: Vec<u8> = vec![1, 2, 3, 4, 5, 0xf, 0xe, 0xd, 0xa, 9, 8];
    let auth_value: Vec<u8> = vec![9, 8, 7, 6, 5];
    let sens_create = TPMS_SENSITIVE_CREATE::new(&auth_value, &data_to_seal);

    let sealed_obj = tpm.Create(&primary, &sens_create, &seal_template, &Default::default(), &Default::default())?;
    let mut sealed_key = tpm.Load(&primary, &sealed_obj.outPrivate, &sealed_obj.outPublic)?;
    sealed_key.set_auth(&auth_value);
    println!("Created sealed object: {:?}", sealed_key);

    // Start a policy session and execute the policy
    let mut sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPCR(&session_handle(&sess), &pcr_digest, &pcr_selection)?;
    tpm.PolicyPassword(&session_handle(&sess))?;
    // After PolicyPassword, set the flag so auth is sent as password
    sess.needs_password = true;

    // Unseal - should succeed with correct auth and PCR
    let unsealed = tpm.with_session(sess.clone()).Unseal(&sealed_key)?;
    println!("Unsealed data: {:?}", unsealed);
    assert_eq!(data_to_seal, unsealed, "Unsealed data should match");
    tpm.FlushContext(&session_handle(&sess))?;

    // Try without auth value - should fail
    sealed_key.set_auth(&[]);
    let mut sess2 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPCR(&session_handle(&sess2), &pcr_digest, &pcr_selection)?;
    tpm.PolicyPassword(&session_handle(&sess2))?;
    sess2.needs_password = true;

    tpm.allow_errors();
    let _ = tpm.with_session(sess2.clone()).Unseal(&sealed_key);
    println!("Unseal without auth: last_rc = {} (expected AUTH_FAIL)", tpm.last_response_code());
    tpm.FlushContext(&session_handle(&sess2))?;

    // Try with wrong PCR value - policy execution should fail
    sealed_key.set_auth(&auth_value);
    tpm.PCR_Event(&TPM_HANDLE::pcr(pcr), &vec![1, 2, 3, 4])?; // change PCR
    let mut sess3 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;

    tpm.allow_errors();
    let _ = tpm.PolicyPCR(&session_handle(&sess3), &pcr_digest, &pcr_selection);
    println!("PolicyPCR with wrong value: last_rc = {} (expected VALUE)", tpm.last_response_code());

    // Try unseal anyway - should fail
    tpm.PolicyPassword(&session_handle(&sess3))?;
    sess3.needs_password = true;
    tpm.allow_errors();
    let _ = tpm.with_session(sess3.clone()).Unseal(&sealed_key);
    println!("Unseal with wrong PCR: last_rc = {} (expected POLICY_FAIL)", tpm.last_response_code());
    tpm.FlushContext(&session_handle(&sess3))?;

    tpm.FlushContext(&sealed_key)?;
    tpm.FlushContext(&primary)?;

    println!("Unseal sample completed successfully");
    Ok(())
}

fn policy_or_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicyOR Sample");

    let bank = TPM_ALG_ID::SHA256;
    let pcr: u32 = 15;

    // Set PCR to a known value
    tpm.PCR_Event(&TPM_HANDLE::pcr(pcr), &vec![1, 2, 3, 4])?;

    let pcr_selection = TPMS_PCR_SELECTION::get_selection_array(bank, pcr);
    let pcr_vals = tpm.PCR_Read(&pcr_selection)?;

    // Compute the PCR digest
    let mut pcr_digest_data = Vec::new();
    for v in &pcr_vals.pcrValues {
        pcr_digest_data.extend_from_slice(&v.buffer);
    }
    let pcr_digest = Crypto::hash(bank, &pcr_digest_data)?;

    // Branch 1: PolicyPCR (current PCR value)
    let trial1 = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPCR(&session_handle(&trial1), &pcr_digest, &pcr_selection)?;
    let branch1_digest = tpm.PolicyGetDigest(&session_handle(&trial1))?;
    tpm.FlushContext(&session_handle(&trial1))?;
    println!("Branch 1 (PolicyPCR) digest: {:?}", branch1_digest);

    // Branch 2: PolicyCommandCode(HMAC_Start)
    let trial2 = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyCommandCode(&session_handle(&trial2), TPM_CC::HMAC_Start)?;
    let branch2_digest = tpm.PolicyGetDigest(&session_handle(&trial2))?;
    tpm.FlushContext(&session_handle(&trial2))?;
    println!("Branch 2 (PolicyCommandCode) digest: {:?}", branch2_digest);

    // Compute the OR policy digest using trial session
    let hash_list = vec![
        TPM2B_DIGEST { buffer: branch1_digest.clone() },
        TPM2B_DIGEST { buffer: branch2_digest.clone() },
    ];

    let trial_or = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyOR(&session_handle(&trial_or), &hash_list)?;
    let or_policy_digest = tpm.PolicyGetDigest(&session_handle(&trial_or))?;
    tpm.FlushContext(&session_handle(&trial_or))?;
    println!("OR policy digest: {:?}", or_policy_digest);

    // Create an HMAC key with the OR policy
    let hmac_key = make_hmac_primary_with_policy(tpm, &or_policy_digest, &[], TPM_ALG_ID::SHA256)?;

    // Use branch 1 (PolicyPCR) - should succeed while PCR is unchanged
    let sess1 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPCR(&session_handle(&sess1), &pcr_digest, &pcr_selection)?;
    tpm.PolicyOR(&session_handle(&sess1), &hash_list)?;

    let hmac_result = tpm.with_session(sess1.clone()).HMAC(&hmac_key, &vec![1, 2, 3, 4], TPM_ALG_ID::SHA256)?;
    println!("Branch 1 HMAC succeeded: {:?}", hmac_result);
    tpm.FlushContext(&session_handle(&sess1))?;

    // Change PCR - branch 1 should now fail
    tpm.PCR_Event(&TPM_HANDLE::pcr(pcr), &vec![5, 6, 7, 8])?;

    let sess2 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.allow_errors();
    let _ = tpm.PolicyPCR(&session_handle(&sess2), &pcr_digest, &pcr_selection);
    println!("Branch 1 after PCR change: last_rc = {} (expected VALUE)", tpm.last_response_code());
    tpm.FlushContext(&session_handle(&sess2))?;

    // Use branch 2 (PolicyCommandCode) - should succeed regardless of PCR
    let sess3 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyCommandCode(&session_handle(&sess3), TPM_CC::HMAC_Start)?;
    tpm.PolicyOR(&session_handle(&sess3), &hash_list)?;

    let hmac_seq = tpm.with_session(sess3.clone()).HMAC_Start(&hmac_key, &vec![], TPM_ALG_ID::SHA256)?;
    println!("Branch 2 HMAC_Start succeeded: {:?}", hmac_seq);
    tpm.FlushContext(&hmac_seq)?;
    tpm.FlushContext(&session_handle(&sess3))?;

    tpm.FlushContext(&hmac_key)?;

    println!("PolicyOR sample completed successfully");
    Ok(())
}

fn policy_with_passwords_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Policy With Passwords Sample");

    // Reset dictionary attack lockout (may fail on some TPMs)
    tpm.allow_errors();
    let _ = tpm.DictionaryAttackLockReset(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()));
    if tpm.last_response_code() != TPM_RC::SUCCESS {
        println!("Note: DictionaryAttackLockReset failed (rc={}), continuing...", tpm.last_response_code());
    }

    // --- PolicyPassword demo ---
    println!(">> PolicyPassword");

    // Compute policy digest for PolicyPassword
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPassword(&session_handle(&trial))?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("PolicyPassword digest: {:?}", policy_digest);

    let use_auth = Crypto::hash(TPM_ALG_ID::SHA256, &b"password".to_vec())?;
    let mut hmac_handle = make_hmac_primary_with_policy(tpm, &policy_digest, &use_auth, TPM_ALG_ID::SHA256)?;
    hmac_handle.set_auth(&use_auth);

    // Works with correct password
    let mut sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPassword(&session_handle(&sess))?;
    sess.needs_password = true;

    let hmac_result = tpm.with_session(sess.clone()).HMAC(&hmac_handle, &vec![1, 2, 3, 4], TPM_ALG_ID::SHA256)?;
    println!("HMAC with correct password: {:?}", hmac_result);
    tpm.FlushContext(&session_handle(&sess))?;

    // Fails without password
    hmac_handle.set_auth(&[]);
    let mut sess2 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPassword(&session_handle(&sess2))?;
    sess2.needs_password = true;

    tpm.allow_errors();
    let _ = tpm.with_session(sess2.clone()).HMAC(&hmac_handle, &vec![1, 2, 3, 4], TPM_ALG_ID::SHA256);
    println!("HMAC without password: last_rc = {} (expected AUTH_FAIL)", tpm.last_response_code());
    tpm.FlushContext(&session_handle(&sess2))?;
    tpm.FlushContext(&hmac_handle)?;

    // --- PolicyAuthValue demo ---
    println!("\n>> PolicyAuthValue");

    let trial2 = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyAuthValue(&session_handle(&trial2))?;
    let policy_digest2 = tpm.PolicyGetDigest(&session_handle(&trial2))?;
    tpm.FlushContext(&session_handle(&trial2))?;
    println!("PolicyAuthValue digest: {:?}", policy_digest2);

    let use_auth2 = Crypto::hash(TPM_ALG_ID::SHA256, &b"password2".to_vec())?;
    let mut hmac_handle2 = make_hmac_primary_with_policy(tpm, &policy_digest2, &use_auth2, TPM_ALG_ID::SHA256)?;
    hmac_handle2.set_auth(&use_auth2);

    // Works with correct auth value (HMAC-based proof of possession)
    let mut sess3 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyAuthValue(&session_handle(&sess3))?;
    sess3.needs_hmac = true;

    let hmac_result2 = tpm.with_session(sess3.clone()).HMAC(&hmac_handle2, &vec![1, 2, 3, 4], TPM_ALG_ID::SHA256)?;
    println!("HMAC with PolicyAuthValue: {:?}", hmac_result2);
    tpm.FlushContext(&session_handle(&sess3))?;

    // Fails without auth value
    hmac_handle2.set_auth(&[]);
    let mut sess4 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyAuthValue(&session_handle(&sess4))?;
    sess4.needs_hmac = true;

    tpm.allow_errors();
    let _ = tpm.with_session(sess4.clone()).HMAC(&hmac_handle2, &vec![1, 2, 3, 4], TPM_ALG_ID::SHA256);
    println!("HMAC without auth value: last_rc = {} (expected AUTH_FAIL)", tpm.last_response_code());
    tpm.FlushContext(&session_handle(&sess4))?;
    tpm.FlushContext(&hmac_handle2)?;

    println!("Policy with passwords sample completed successfully");
    Ok(())
}

fn import_duplicate_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Import/Duplicate Sample");

    // Create storage primary
    let primary = make_storage_primary(tpm)?;
    println!("Created storage primary: {:?}", primary);

    // Compute policy for Duplicate command
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyCommandCode(&session_handle(&trial), TPM_CC::Duplicate)?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("Duplicate policy digest: {:?}", policy_digest);

    // Create a signing key that allows duplication (via policy)
    let key_attrs = TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth
        | TPMA_OBJECT::sensitiveDataOrigin;
    let key_parms = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
        &Default::default(),
        &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA { hashAlg: TPM_ALG_ID::SHA256 })),
        2048, 65537,
    ));
    let key_template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA256, key_attrs, &policy_digest,
        &Some(key_parms),
        &Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    );

    let new_key = tpm.Create(&primary, &Default::default(), &key_template,
                              &Default::default(), &Default::default())?;
    let sign_key = tpm.Load(&primary, &new_key.outPrivate, &new_key.outPublic)?;
    println!("Created duplicatable signing key: {:?}", sign_key);

    // Duplicate using policy session
    let sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyCommandCode(&session_handle(&sess), TPM_CC::Duplicate)?;

    let null_parent = TPM_HANDLE::new(TPM_RH::NULL.get_value());
    let no_sym = TPMT_SYM_DEF_OBJECT::default();
    println!("About to call Duplicate...");
    let dup_result = tpm.with_session(sess.clone()).Duplicate(
        &sign_key, &null_parent, &vec![], &no_sym)?;
    println!("Duplicated key successfully");
    tpm.FlushContext(&session_handle(&sess))?;
    tpm.FlushContext(&sign_key)?;

    // Import the key back to the same parent (with no outer wrapper)
    let imported = tpm.Import(&primary, &vec![], &new_key.outPublic,
                               &dup_result.duplicate, &vec![], &no_sym)?;
    println!("Imported key back");

    // Load the imported key and sign with it
    let imported_key = tpm.Load(&primary, &imported, &new_key.outPublic)?;
    let data_to_sign = Crypto::hash(TPM_ALG_ID::SHA256, &b"test import".to_vec())?;
    let sig = tpm.Sign(&imported_key, &data_to_sign,
                        &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?,
                        &TPMT_TK_HASHCHECK::default())?;
    println!("Signed with imported key: {:?}", sig.is_some());

    tpm.FlushContext(&imported_key)?;
    tpm.FlushContext(&primary)?;

    println!("Import/Duplicate sample completed successfully");
    Ok(())
}

fn policy_counter_timer_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicyCounterTimer Sample");

    // PolicyCounterTimer allows actions to be gated on the TPM's clocks and timers.
    // Here we demonstrate giving a user owner-privileges for ~5 seconds.

    let start_clock = tpm.ReadClock()?;
    let now_time = start_clock.time;
    let end_time = now_time + 5 * 1000; // 5 seconds from now

    // Construct the operand: UINT64 big-endian representation of end_time
    let operand = end_time.to_be_bytes().to_vec();

    // Compute the policy digest using trial session
    // PolicyCounterTimer(endTime, offset=0, UNSIGNED_LT) means:
    // "Allow if TPMS_TIME_INFO.time < endTime"
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyCounterTimer(&session_handle(&trial), &operand, 0, TPM_EO::UNSIGNED_LT)?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("PolicyCounterTimer digest: {:?}", policy_digest);

    // Set the owner policy to this value
    tpm.SetPrimaryPolicy(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
                          &policy_digest, TPM_ALG_ID::SHA256)?;

    // Now try using the policy a few times - should succeed until time expires
    println!("Operations should start failing in about 5 seconds...");

    for i in 0..4 {
        let sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
        tpm.allow_errors();
        let _ = tpm.PolicyCounterTimer(&session_handle(&sess), &operand, 0, TPM_EO::UNSIGNED_LT);
        let timer_ok = tpm.last_response_code() == TPM_RC::SUCCESS;

        if timer_ok {
            tpm.allow_errors();
            let _ = tpm.with_session(sess.clone()).SetPrimaryPolicy(
                &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
                &policy_digest, TPM_ALG_ID::SHA256);
            if tpm.last_response_code() == TPM_RC::SUCCESS {
                println!("Iteration {}: Succeeded", i);
            } else {
                println!("Iteration {}: Policy valid but command failed (rc={})", i, tpm.last_response_code());
            }
        } else {
            println!("Iteration {}: Policy expired (rc={})", i, tpm.last_response_code());
        }
        tpm.FlushContext(&session_handle(&sess))?;
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }

    // Put things back the way they were
    tpm.SetPrimaryPolicy(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
                          &vec![], TPM_ALG_ID::NULL)?;

    println!("PolicyCounterTimer sample completed successfully");
    Ok(())
}

fn policy_secret_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicySecret Sample");

    // PolicySecret demands proof-of-knowledge of the admin auth value.
    // The TPM verifies the auth by using a policy session that references
    // the OWNER hierarchy handle.

    // Use trial session to compute policy digest for PolicySecret(OWNER)
    let owner_handle = TPM_HANDLE::new(TPM_RH::OWNER.get_value());

    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicySecret(&owner_handle, &session_handle(&trial),
                      &vec![], &vec![], &vec![], 0)?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("PolicySecret digest: {:?}", policy_digest);

    // Make an object with this policy
    let hmac_key = make_hmac_primary_with_policy(tpm, &policy_digest, &[], TPM_ALG_ID::SHA256)?;

    // Now run the policy: this will use PWAP to prove knowledge of the admin password
    let sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicySecret(&owner_handle, &session_handle(&sess),
                      &vec![], &vec![], &vec![], 0)?;

    // Use the session to authorize HMAC_Start
    let hmac_seq = tpm.with_session(sess.clone()).HMAC_Start(&hmac_key, &vec![], TPM_ALG_ID::SHA256)?;
    println!("PolicySecret-authorized HMAC_Start succeeded: {:?}", hmac_seq);

    tpm.FlushContext(&hmac_seq)?;
    tpm.FlushContext(&session_handle(&sess))?;
    tpm.FlushContext(&hmac_key)?;

    println!("PolicySecret sample completed successfully");
    Ok(())
}

fn policy_nv_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicyNV Sample");

    // PolicyNV allows actions to be gated on the contents of an NV-storage slot

    let nv_auth: Vec<u8> = vec![1, 5, 1, 1];
    let nv_index: u32 = 0x01500030; // Use a different index to avoid conflicts
    let mut nv_handle = TPM_HANDLE::new(nv_index);

    // Try to delete the slot if it exists (ignore failure)
    {
        tpm.allow_errors();
        let _ = tpm.NV_UndefineSpace(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &nv_handle);
    }

    // Make a new simple NV slot, 16 bytes, RW with auth
    let nv_template = TPMS_NV_PUBLIC::new(
        &TPM_HANDLE::new(nv_index),
        TPM_ALG_ID::SHA256,
        TPMA_NV::AUTHREAD | TPMA_NV::AUTHWRITE,
        &vec![],
        16,
    );

    tpm.NV_DefineSpace(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &nv_auth, &nv_template)?;
    nv_handle.set_auth(&nv_auth);
    println!("Defined NV slot at 0x{:08x}", nv_index);

    // Write some data
    let to_write: Vec<u8> = vec![1, 2, 3, 4, 5, 4, 3, 2, 1];
    tpm.NV_Write(&nv_handle, &nv_handle, &to_write, 0)?;
    println!("NV_Write succeeded");

    // Read back the NV public info to get the name
    let nv_info = tpm.NV_ReadPublic(&nv_handle)?;
    nv_handle.name = nv_info.nvName.clone();
    println!("NV_ReadPublic succeeded, name len={}", nv_info.nvName.len());

    // Compute PolicyNV digest using trial session
    // Use the NV handle as auth handle (with proper auth)
    println!("Starting PolicyNV trial session...");
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    println!("Trial session started, calling PolicyNV...");
    tpm.PolicyNV(&nv_handle, &nv_handle, &session_handle(&trial),
                  &to_write, 0, TPM_EO::EQ)?;
    println!("PolicyNV succeeded in trial session");
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("PolicyNV digest: {:?}", policy_digest);

    // Create HMAC key with PolicyNV policy
    let hmac_key = make_hmac_primary_with_policy(tpm, &policy_digest, &[], TPM_ALG_ID::SHA256)?;

    // Use the policy - should succeed when NV matches
    let sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyNV(&nv_handle, &nv_handle, &session_handle(&sess),
                  &to_write, 0, TPM_EO::EQ)?;

    let hmac_result = tpm.with_session(sess.clone()).HMAC(&hmac_key, &vec![1, 2, 3], TPM_ALG_ID::SHA256)?;
    println!("HMAC with correct NV: {:?}", hmac_result);
    tpm.FlushContext(&session_handle(&sess))?;

    // Change NV data and verify policy fails
    tpm.NV_Write(&nv_handle, &nv_handle, &vec![3, 1], 0)?;

    let sess2 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.allow_errors();
    let _ = tpm.PolicyNV(&nv_handle, &nv_handle, &session_handle(&sess2),
                          &to_write, 0, TPM_EO::EQ);
    println!("PolicyNV with changed data: last_rc = {} (expected POLICY_FAIL)", tpm.last_response_code());
    tpm.FlushContext(&session_handle(&sess2))?;

    // Cleanup
    tpm.FlushContext(&hmac_key)?;
    tpm.NV_UndefineSpace(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &nv_handle)?;

    println!("PolicyNV sample completed successfully");
    Ok(())
}

fn software_keys_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Software Keys Sample");

    // This sample demonstrates creating a duplicatable key in the TPM,
    // exporting it via Duplicate, re-importing it, and signing with both.

    let primary = make_storage_primary(tpm)?;

    // Compute policy for Duplicate command
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyCommandCode(&session_handle(&trial), TPM_CC::Duplicate)?;
    let dup_policy = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;

    // Create a duplicatable signing key
    let key_attrs = TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth
        | TPMA_OBJECT::sensitiveDataOrigin;
    let key_parms = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
        &Default::default(),
        &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA { hashAlg: TPM_ALG_ID::SHA256 })),
        2048, 65537,
    ));
    let key_template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA256, key_attrs, &dup_policy,
        &Some(key_parms),
        &Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    );

    let key_data = tpm.Create(&primary, &Default::default(), &key_template,
                               &Default::default(), &Default::default())?;
    let tpm_key = tpm.Load(&primary, &key_data.outPrivate, &key_data.outPublic)?;
    println!("Created duplicatable signing key in TPM");

    // Sign with the TPM key
    let to_sign = Crypto::hash(TPM_ALG_ID::SHA256, &b"hello from software key".to_vec())?;
    let tpm_sig = tpm.Sign(&tpm_key, &to_sign,
                            &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?,
                            &TPMT_TK_HASHCHECK::default())?;
    println!("Signed with TPM-created key: {:?}", tpm_sig.is_some());

    // Verify with VerifySignature
    let verify_result = tpm.VerifySignature(&tpm_key, &to_sign, &tpm_sig)?;
    println!("TPM verified its own signature: hierarchy={:?}", verify_result.hierarchy);

    // Duplicate the key out (unwrapped, no encryption)
    let dup_sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyCommandCode(&session_handle(&dup_sess), TPM_CC::Duplicate)?;

    let null_parent = TPM_HANDLE::new(TPM_RH::NULL.get_value());
    let dup = tpm.with_session(dup_sess.clone()).Duplicate(
        &tpm_key, &null_parent, &vec![], &TPMT_SYM_DEF_OBJECT::default())?;
    println!("Exported key via Duplicate");

    tpm.FlushContext(&session_handle(&dup_sess))?;
    tpm.FlushContext(&tpm_key)?;

    // Re-import the duplicated key
    let re_imported = tpm.Import(&primary, &vec![], &key_data.outPublic,
                                  &dup.duplicate, &vec![], &TPMT_SYM_DEF_OBJECT::default())?;
    let re_key = tpm.Load(&primary, &re_imported, &key_data.outPublic)?;
    println!("Re-imported duplicated key");

    // Sign with the re-imported key
    let re_sig = tpm.Sign(&re_key, &to_sign,
                           &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?,
                           &TPMT_TK_HASHCHECK::default())?;
    println!("Signed with re-imported key: {:?}", re_sig.is_some());

    // Verify the re-imported key signature with the original public key
    let verify2 = tpm.VerifySignature(&re_key, &to_sign, &re_sig)?;
    println!("Verified re-imported key signature: hierarchy={:?}", verify2.hierarchy);

    tpm.FlushContext(&re_key)?;
    tpm.FlushContext(&primary)?;

    println!("Software keys sample completed successfully");
    Ok(())
}

fn policy_pcr_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Policy PCR Sample");

    let bank = TPM_ALG_ID::SHA256;
    let pcr: u32 = 15;

    // Set PCR to a known value
    tpm.PCR_Event(&TPM_HANDLE::pcr(pcr), &vec![1, 2, 3, 4])?;

    let pcr_selection = TPMS_PCR_SELECTION::get_selection_array(bank, pcr);
    let pcr_vals = tpm.PCR_Read(&pcr_selection)?;

    // Compute the PCR digest
    let mut pcr_digest_data = Vec::new();
    for v in &pcr_vals.pcrValues {
        pcr_digest_data.extend_from_slice(&v.buffer);
    }
    let pcr_digest = Crypto::hash(bank, &pcr_digest_data)?;

    // Compute policy digest using trial session
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPCR(&session_handle(&trial), &pcr_digest, &pcr_selection)?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("PolicyPCR digest: {:?}", policy_digest);

    // Create HMAC key with PCR policy
    let hmac_key = make_hmac_primary_with_policy(tpm, &policy_digest, &[], TPM_ALG_ID::SHA256)?;

    // Succeeds when PCR matches
    let sess = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.PolicyPCR(&session_handle(&sess), &pcr_digest, &pcr_selection)?;
    let hmac_result = tpm.with_session(sess.clone()).HMAC(&hmac_key, &vec![1, 2, 3, 4], TPM_ALG_ID::SHA256)?;
    println!("HMAC with correct PCR: {:?}", hmac_result);
    tpm.FlushContext(&session_handle(&sess))?;

    // Change PCR - should fail
    tpm.PCR_Event(&TPM_HANDLE::pcr(pcr), &vec![5, 6, 7, 8])?;
    let sess2 = tpm.start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)?;
    tpm.allow_errors();
    let _ = tpm.PolicyPCR(&session_handle(&sess2), &pcr_digest, &pcr_selection);
    println!("PolicyPCR with wrong value: last_rc = {} (expected VALUE)", tpm.last_response_code());
    tpm.FlushContext(&session_handle(&sess2))?;

    tpm.FlushContext(&hmac_key)?;

    println!("Policy PCR sample completed successfully");
    Ok(())
}

fn policy_cphash_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicyCpHash Sample");

    // PolicyCpHash restricts the actions that can be performed with a secured object
    // to a specific operation identified by the hash of the command parameters.
    //
    // Approach: compute the policy digest using a trial session, then create a key
    // with that policy. The tricky part is that cpHash depends on the key's name,
    // which isn't known until the key is created. So we use a two-step approach:
    // 1. Create a key with just PolicyCommandCode
    // 2. Show that PolicyCpHash works in trial sessions

    let hash_alg = TPM_ALG_ID::SHA256;

    // Compute trial PolicyCpHash to demonstrate how it works
    // cpHash = H(cc || handle_names || parameters)
    // We'll use a dummy hash value for the trial
    let dummy_cphash = Crypto::hash(hash_alg, b"example cpHash input")?;

    let trial = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyCpHash(&session_handle(&trial), &dummy_cphash)?;
    let cphash_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("PolicyCpHash trial digest: {:?}", &cphash_digest[..8]);

    // Also combine with PolicyCommandCode
    let trial2 = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyCpHash(&session_handle(&trial2), &dummy_cphash)?;
    tpm.PolicyCommandCode(&session_handle(&trial2), TPM_CC::HMAC_Start)?;
    let combined_digest = tpm.PolicyGetDigest(&session_handle(&trial2))?;
    tpm.FlushContext(&session_handle(&trial2))?;
    println!("PolicyCpHash + PolicyCommandCode trial digest: {:?}", &combined_digest[..8]);
    println!("(Demonstrates policy digest computation - cpHash restricts to specific parameters)");

    println!("PolicyCpHash sample completed successfully");
    Ok(())
}

fn policy_name_hash_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicyNameHash Sample");

    // PolicyNameHash restricts a policy to only authorize operations when specific
    // handles are used. We demonstrate computing the policy digest.
    //
    // Note: PolicyNameHash is typically used to restrict which handles can be used
    // with admin operations. Since modifying hierarchy auth on a real TPM is risky
    // (DA lockout can prevent recovery), we demonstrate the policy computation
    // using trial sessions.

    let hash_alg = TPM_ALG_ID::SHA256;

    // Compute nameHash for the OWNER handle
    let owner_name = TPM_HANDLE::new(TPM_RH::OWNER.get_value()).get_name()?;
    let name_hash = Crypto::hash(hash_alg, &owner_name)?;
    println!("nameHash(OWNER): {:?}", &name_hash[..8]);

    // Build policy digest using trial session
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyNameHash(&session_handle(&trial), &name_hash)?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("PolicyNameHash trial digest: {:?}", &policy_digest[..8]);

    // Combine with PolicyCommandCode for a more realistic policy
    let trial2 = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyNameHash(&session_handle(&trial2), &name_hash)?;
    tpm.PolicyCommandCode(&session_handle(&trial2), TPM_CC::HierarchyChangeAuth)?;
    let combined_digest = tpm.PolicyGetDigest(&session_handle(&trial2))?;
    tpm.FlushContext(&session_handle(&trial2))?;
    println!("PolicyNameHash + PolicyCommandCode trial digest: {:?}", &combined_digest[..8]);
    println!("(Demonstrates policy that restricts HierarchyChangeAuth to OWNER handle only)");

    println!("PolicyNameHash sample completed successfully");
    Ok(())
}

fn rewrap_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("ReWrap Sample");

    // Make an exportable key with Duplicate policy, duplicate it with no encryption,
    // then rewrap it to a new parent.

    let hash_alg = TPM_ALG_ID::SHA256;

    // Compute policy for Duplicate command
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyCommandCode(&session_handle(&trial), TPM_CC::Duplicate)?;
    let dup_policy = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;

    // Create a duplicatable storage primary
    let dup_attrs = TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;
    let dup_parms = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
        &Aes128Cfb,
        &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
        2048, 65537,
    ));
    let dup_template = TPMT_PUBLIC::new(
        hash_alg, dup_attrs, &dup_policy,
        &Some(dup_parms),
        &Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    );

    let dup_key_resp = tpm.CreatePrimary(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &TPMS_SENSITIVE_CREATE::default(),
        &dup_template,
        &Default::default(),
        &Default::default(),
    )?;
    let dup_key = dup_key_resp.handle;

    // Make a new storage parent
    let new_parent = make_storage_primary(tpm)?;

    // Duplicate the key to NULL parent (plaintext export, no encryption)
    let sess = tpm.start_auth_session(TPM_SE::POLICY, hash_alg)?;
    tpm.PolicyCommandCode(&session_handle(&sess), TPM_CC::Duplicate)?;
    let dup_resp = tpm.with_session(sess.clone()).Duplicate(
        &dup_key, &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        &vec![], &Default::default(),
    )?;
    println!("Duplicated key (plaintext), duplicate size: {}", dup_resp.duplicate.buffer.len());
    tpm.FlushContext(&session_handle(&sess))?;

    // Rewrap from NULL parent to new parent
    let rewrap_resp = tpm.Rewrap(
        &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        &new_parent,
        &dup_resp.duplicate,
        &dup_key.get_name()?,
        &vec![],  // No sym seed since duplicated to NULL
    )?;
    println!("Rewrapped key to new parent, outDuplicate size: {}", rewrap_resp.outDuplicate.buffer.len());

    tpm.FlushContext(&dup_key)?;
    tpm.FlushContext(&new_parent)?;

    println!("ReWrap sample completed successfully");
    Ok(())
}

fn audit_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Audit Sample");

    // The TPM supports command audit - keeping a running hash of commands/responses
    // for commands in a specified list.

    let audit_alg = TPM_ALG_ID::SHA256;
    let owner_handle = TPM_HANDLE::new(TPM_RH::OWNER.get_value());
    let empty_cc: Vec<TPM_CC> = vec![];

    // Reset audit status
    tpm.SetCommandCodeAuditStatus(&owner_handle, TPM_ALG_ID::NULL, &empty_cc, &empty_cc)?;

    // Start auditing GetRandom and StirRandom
    let to_audit = vec![TPM_CC::GetRandom, TPM_CC::StirRandom];
    tpm.SetCommandCodeAuditStatus(&owner_handle, audit_alg, &empty_cc, &empty_cc)?;
    tpm.SetCommandCodeAuditStatus(&owner_handle, TPM_ALG_ID::NULL, &to_audit, &empty_cc)?;
    println!("Set up command audit for GetRandom and StirRandom");

    // Read the audit digest before our commands
    let audit_before = tpm.GetCommandAuditDigest(
        &TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()),
        &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        &vec![],
        &Some(TPMU_SIG_SCHEME::null(TPMS_NULL_SIG_SCHEME::default())),
    )?;
    println!("Audit digest before commands: {:?}", &audit_before.auditInfo.attested);

    // Execute some audited commands
    let _ = tpm.GetRandom(20)?;
    tpm.StirRandom(&vec![1, 2, 3, 4])?;
    let _ = tpm.GetRandom(10)?;
    tpm.StirRandom(&vec![9, 8, 7, 6])?;
    println!("Executed 4 audited commands");

    // Stop auditing
    tpm.SetCommandCodeAuditStatus(&owner_handle, TPM_ALG_ID::NULL, &empty_cc, &empty_cc)?;

    // Read the audit digest after commands
    let audit_after = tpm.GetCommandAuditDigest(
        &TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()),
        &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        &vec![],
        &Some(TPMU_SIG_SCHEME::null(TPMS_NULL_SIG_SCHEME::default())),
    )?;
    println!("Audit digest after commands: {:?}", &audit_after.auditInfo.attested);

    // Now demonstrate session audit
    println!("\n>> Session Audit");

    // Create a signing key for the session audit quote
    let primary = make_storage_primary(tpm)?;
    let sig_key = make_child_signing_key(tpm, &primary, true)?;
    tpm.FlushContext(&primary)?;

    // Start an HMAC session with audit attribute
    let audit_attrs = TPMA_SESSION::audit | TPMA_SESSION::continueSession;
    let sess = tpm.start_auth_session_full(
        TPM_SE::HMAC, audit_alg,
        audit_attrs,
        TPMT_SYM_DEF::default(),
    )?;

    // Execute some commands in the audit session
    tpm.with_session(sess.clone()).GetRandom(20)?;
    let sess = tpm.last_session().unwrap();
    tpm.with_session(sess.clone()).StirRandom(&vec![1, 2, 3, 4])?;
    let sess = tpm.last_session().unwrap();

    // Get the session audit digest
    let session_quote = tpm.GetSessionAuditDigest(
        &TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()),
        &sig_key,
        &session_handle(&sess),
        &vec![],
        &Some(TPMU_SIG_SCHEME::null(TPMS_NULL_SIG_SCHEME::default())),
    )?;
    println!("Session audit quote obtained");
    println!("Session audit attested: {:?}", &session_quote.auditInfo.attested);

    tpm.FlushContext(&session_handle(&sess))?;
    tpm.FlushContext(&sig_key)?;

    println!("Audit sample completed successfully");
    Ok(())
}

fn policy_locality_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicyLocality Sample (trial only)");

    // PolicyLocality restricts key usage to specific TPM localities.
    // On real hardware (TBS), we can't change locality, so we only
    // demonstrate computing the policy digest.

    let hash_alg = TPM_ALG_ID::SHA256;

    // Build policy digest using trial session
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyLocality(&session_handle(&trial), TPMA_LOCALITY::LOC_ONE)?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;

    println!("PolicyLocality(LOC_ONE) digest: {:?}", &policy_digest[..8]);

    // Create a key with this policy
    let hmac_key = make_hmac_primary_with_policy(tpm, &policy_digest, &[], hash_alg)?;
    println!("Created HMAC key with locality policy");

    // Try to use with a policy session - will fail since we can't set locality on TBS
    let sess = tpm.start_auth_session(TPM_SE::POLICY, hash_alg)?;
    tpm.allow_errors();
    let _ = tpm.PolicyLocality(&session_handle(&sess), TPMA_LOCALITY::LOC_ONE);
    println!("PolicyLocality in real session: last_rc = {} (expected LOCALITY on TBS)", tpm.last_response_code());
    tpm.FlushContext(&session_handle(&sess))?;

    tpm.FlushContext(&hmac_key)?;

    println!("PolicyLocality sample completed (trial only on TBS)");
    Ok(())
}

fn async_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Async Sample");

    // The TPM supports asynchronous command dispatch: you send the command,
    // then poll for completion, and finally retrieve the result.
    // On Windows TBS, commands complete synchronously, but the API pattern
    // is still useful for non-blocking designs and other transport layers.

    // Fast async operation: GetRandom
    println!(">> Async GetRandom");
    {
        let mut async_tpm = tpm.async_methods();
        async_tpm.GetRandom_async(16)?;
    }
    // On TBS, response is immediately available
    {
        let mut async_tpm = tpm.async_methods();
        let rand_data = async_tpm.GetRandom_complete()?;
        println!("Async random data ({} bytes): {:?}", rand_data.len(), &rand_data[..8]);
    }

    // Slow async operation: CreatePrimary
    println!(">> Async CreatePrimary");
    let object_attributes = TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent
        | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin
        | TPMA_OBJECT::userWithAuth;
    let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
        &Default::default(),
        &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA { hashAlg: TPM_ALG_ID::SHA256 })),
        2048, 65537,
    ));
    let template = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA1, object_attributes, &Default::default(),
        &Some(parameters),
        &Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    );

    {
        let mut async_tpm = tpm.async_methods();
        async_tpm.CreatePrimary_async(
            &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
            &TPMS_SENSITIVE_CREATE::default(),
            &template,
            &Default::default(),
            &Default::default(),
        )?;
    }

    let new_primary = {
        let mut async_tpm = tpm.async_methods();
        async_tpm.CreatePrimary_complete()?
    };

    println!("Asynchronously created primary key: handle={:?}", new_primary.handle);
    tpm.FlushContext(&new_primary.handle)?;

    println!("Async sample completed successfully");
    Ok(())
}

fn session_encryption_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("SessionEncryption Sample");

    // Session encryption is transparent to the application programmer.
    // Create a session with decrypt/encrypt attributes and the library handles
    // the AES-CFB encryption/decryption of the first parameter automatically.

    // Part 1: Encrypt commands TO the TPM (decrypt attribute)
    println!(">> Encrypt commands to TPM (TPMA_SESSION::decrypt)");
    let sess = tpm.start_auth_session_full(
        TPM_SE::HMAC, TPM_ALG_ID::SHA256,
        TPMA_SESSION::continueSession | TPMA_SESSION::decrypt,
        TPMT_SYM_DEF::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
    )?;

    // StirRandom: the stirValue buffer will be encrypted before sending to TPM
    tpm.with_session(sess.clone()).StirRandom(&vec![1, 1, 1, 1, 1, 1, 1, 1])?;
    let sess = tpm.last_session().unwrap();
    println!("StirRandom with encrypted parameter succeeded");

    // Do it again to verify continueSession nonce rolling works
    tpm.with_session(sess.clone()).StirRandom(&vec![2, 2, 2, 2])?;
    let sess = tpm.last_session().unwrap();
    println!("Second StirRandom with encrypted parameter succeeded");

    tpm.FlushContext(&session_handle(&sess))?;

    // Part 2: Encrypt responses FROM the TPM (encrypt attribute)
    println!("\n>> Encrypt responses from TPM (TPMA_SESSION::encrypt)");

    // Create a primary key so we have something to read
    let storage_primary = make_storage_primary(tpm)?;

    // Read public key without encryption
    let plaintext_read = tpm.ReadPublic(&storage_primary)?;

    // Make an encrypting session for response
    let enc_sess = tpm.start_auth_session_full(
        TPM_SE::HMAC, TPM_ALG_ID::SHA256,
        TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
        TPMT_SYM_DEF::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
    )?;

    // ReadPublic with encrypted response - the library should decrypt automatically
    let encrypted_read = tpm.with_session(enc_sess.clone()).ReadPublic(&storage_primary)?;
    let enc_sess = tpm.last_session().unwrap();

    // Compare: the decrypted response should match the plaintext
    if plaintext_read.outPublic.nameAlg == encrypted_read.outPublic.nameAlg
        && plaintext_read.name == encrypted_read.name
    {
        println!("Return parameter encryption succeeded: plaintext and decrypted responses match");
    } else {
        println!("Warning: Responses differ (may indicate encryption/decryption issue)");
    }

    tpm.FlushContext(&session_handle(&enc_sess))?;
    tpm.FlushContext(&storage_primary)?;

    println!("SessionEncryption sample completed successfully");
    Ok(())
}

fn policy_signed_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicySigned");

    // PolicySigned allows a policy to be satisfied by a signature from a specific key.
    // We create a software RSA key, load its public part into the TPM, and then
    // sign the nonce to satisfy the policy.

    let hash_alg = TPM_ALG_ID::SHA256;

    // Create a SW signing key
    let mut sw_key = TSS_KEY::default();
    sw_key.publicPart = TPMT_PUBLIC {
        nameAlg: hash_alg,
        objectAttributes: TPMA_OBJECT(
            TPMA_OBJECT::sign.get_value() | TPMA_OBJECT::userWithAuth.get_value(),
        ),
        authPolicy: vec![],
        parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS {
            symmetric: TPMT_SYM_DEF_OBJECT::default(),
            scheme: Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA {
                hashAlg: hash_alg,
            })),
            keyBits: 2048,
            exponent: 0,
        })),
        unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    };
    sw_key.create_key()?;
    println!("Created software RSA-2048 signing key");

    // Load the public part into the TPM (NULL hierarchy = external key)
    let auth_key_handle = tpm.LoadExternal(
        &TPMT_SENSITIVE::default(),
        &sw_key.publicPart,
        &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
    )?;
    println!("Loaded SW key public part into TPM: {:?}", auth_key_handle);

    // Step 1: Compute trial policy digest for PolicySigned
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    let policy_ref: Vec<u8> = vec![];
    // PolicySigned updates the digest as:
    //   policyDigest = H(policyDigest || TPM_CC_PolicySigned || keyName || policyRef)
    tpm.PolicySigned(
        &auth_key_handle,
        &session_handle(&trial),
        &vec![],      // nonceTPM (ignored in trial)
        &vec![],      // cpHashA
        &policy_ref,
        0,            // expiration
        &Some(TPMU_SIGNATURE::null(TPMS_NULL_SIGNATURE::default())), // no sig needed for trial
    )?;
    let policy_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;
    println!("PolicySigned trial digest: {:?}", &policy_digest[..8]);

    // Step 2: Start a real policy session
    let policy_sess = tpm.start_auth_session(TPM_SE::POLICY, hash_alg)?;
    let nonce_tpm = policy_sess.sess_out.nonce.clone();

    // Step 3: Compute aHash = Hash(nonceTPM || expiration || cpHashA || policyRef)
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(&nonce_tpm);
    to_hash.extend_from_slice(&0i32.to_be_bytes()); // expiration = 0
    // cpHashA is empty, policyRef is empty
    let a_hash = Crypto::hash(hash_alg, &to_hash)?;

    // Step 4: Sign the aHash with our SW key
    let signature = sw_key.sign(&a_hash, hash_alg)?;
    println!("Signed aHash ({} bytes) with SW key", a_hash.len());

    // Step 5: Execute PolicySigned with the real signature
    tpm.PolicySigned(
        &auth_key_handle,
        &session_handle(&policy_sess),
        &nonce_tpm,
        &vec![],      // cpHashA
        &policy_ref,
        0,            // expiration
        &signature.signature,
    )?;

    // Verify the policy digest matches the trial
    let actual_digest = tpm.PolicyGetDigest(&session_handle(&policy_sess))?;
    if actual_digest == policy_digest {
        println!("PolicySigned policy digest is correct");
    } else {
        println!("Warning: policy digest mismatch");
    }

    // Demonstrate PolicyRestart
    tpm.PolicyRestart(&session_handle(&policy_sess))?;
    let reset_digest = tpm.PolicyGetDigest(&session_handle(&policy_sess))?;
    if reset_digest.iter().all(|&b| b == 0) {
        println!("PolicyRestart correctly reset the digest");
    }

    tpm.FlushContext(&session_handle(&policy_sess))?;
    tpm.FlushContext(&auth_key_handle)?;

    println!("PolicySigned sample completed successfully");
    Ok(())
}

fn policy_authorize_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicyAuthorize");

    // PolicyAuthorize lets a key holder transform a policyHash into a new
    // policyHash derived from a public key, if the corresponding private key
    // holder authorizes the pre-policy-hash with a signature.

    let hash_alg = TPM_ALG_ID::SHA256;

    // Create a software signing key (the "authorizing" key)
    let mut sw_key = TSS_KEY::default();
    sw_key.publicPart = TPMT_PUBLIC {
        nameAlg: hash_alg,
        objectAttributes: TPMA_OBJECT(
            TPMA_OBJECT::sign.get_value() | TPMA_OBJECT::userWithAuth.get_value(),
        ),
        authPolicy: vec![],
        parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS {
            symmetric: TPMT_SYM_DEF_OBJECT::default(),
            scheme: Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA {
                hashAlg: hash_alg,
            })),
            keyBits: 2048,
            exponent: 0,
        })),
        unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    };
    sw_key.create_key()?;
    println!("Created authorizing SW key");

    // Load the public part into the TPM
    let auth_key_handle = tpm.LoadExternal(
        &TPMT_SENSITIVE::default(),
        &sw_key.publicPart,
        &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
    )?;

    // Get the authorizing key name
    let key_name = sw_key.publicPart.get_name()?;

    // Step 1: Get the pre-policy digest we want to authorize (PolicyLocality(LOC_ONE))
    let trial_pre = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyLocality(&session_handle(&trial_pre), TPMA_LOCALITY::LOC_ONE)?;
    let pre_digest = tpm.PolicyGetDigest(&session_handle(&trial_pre))?;
    tpm.FlushContext(&session_handle(&trial_pre))?;
    println!("Pre-digest (PolicyLocality): {:?}", &pre_digest[..8]);

    // Step 2: Sign the approvedPolicy as defined in the spec:
    //   aHash = Hash(approvedPolicy || policyRef)
    let policy_ref: Vec<u8> = vec![];
    let mut a_hash_data = Vec::new();
    a_hash_data.extend_from_slice(&pre_digest);
    a_hash_data.extend_from_slice(&policy_ref);
    let a_hash = Crypto::hash(hash_alg, &a_hash_data)?;

    let signature = sw_key.sign(&a_hash, hash_alg)?;
    println!("Signed approvedPolicy with authorizing key");

    // Step 3: Use VerifySignature to get a validation ticket
    let check_ticket = tpm.VerifySignature(
        &auth_key_handle,
        &a_hash,
        &signature.signature,
    )?;
    println!("Got verification ticket from TPM");

    // Step 4: Execute the policy
    // Start a real policy session
    let policy_sess = tpm.start_auth_session(TPM_SE::POLICY, hash_alg)?;

    // First execute the sub-policy (PolicyLocality)
    tpm.PolicyLocality(&session_handle(&policy_sess), TPMA_LOCALITY::LOC_ONE)?;

    // Then call PolicyAuthorize to transform the digest
    tpm.PolicyAuthorize(
        &session_handle(&policy_sess),
        &pre_digest,
        &policy_ref,
        &key_name,
        &check_ticket,
    )?;

    let actual_digest = tpm.PolicyGetDigest(&session_handle(&policy_sess))?;

    // Compute expected: PolicyUpdate for PolicyAuthorize
    //   policyDigest_new = H(0...0 || TPM_CC_PolicyAuthorize || keyName || policyRef)
    let hash_len = Crypto::hash(hash_alg, &[])?.len();
    let mut expected_data = vec![0u8; hash_len];
    expected_data.extend_from_slice(&TPM_CC::PolicyAuthorize.get_value().to_be_bytes());
    expected_data.extend_from_slice(&key_name);
    // policyRef is empty, no need to extend
    let expected_digest = Crypto::hash(hash_alg, &expected_data)?;

    if actual_digest == expected_digest {
        println!("PolicyAuthorize digest is correct");
    } else {
        println!("PolicyAuthorize digest: {:?}", &actual_digest[..8]);
        println!("Expected digest:        {:?}", &expected_digest[..8]);
    }

    tpm.FlushContext(&session_handle(&policy_sess))?;
    tpm.FlushContext(&auth_key_handle)?;

    println!("PolicyAuthorize sample completed successfully");
    Ok(())
}

fn admin_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Administration");

    // This sample demonstrates some TPM administration functions.

    // Note: Clear, ChangePPS, ChangeEPS, HierarchyControl, and SetPrimaryPolicy
    // with locality require Platform auth or locality control, which are not
    // available on TBS. Those are skipped here (as in the C++ sample when
    // PlatformAvailable() returns false).

    // --- HierarchyChangeAuth ---
    // We can change the authValue for the owner hierarchy.
    println!(">> HierarchyChangeAuth");

    let new_owner_auth = Crypto::hash(TPM_ALG_ID::SHA1, b"passw0rd")?;
    println!("Setting OWNER auth to hash of 'passw0rd': {} bytes", new_owner_auth.len());

    tpm.HierarchyChangeAuth(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &new_owner_auth,
    )?;
    println!("OWNER auth changed successfully");

    // TSS.Rust tracks changes of auth-values and updates the relevant handle.
    // Because we have the new auth-value we can continue managing the TPM.
    // Now set it back to empty.
    tpm.HierarchyChangeAuth(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        &vec![],
    )?;
    println!("OWNER auth reset to empty");

    // --- Demonstrate that primary keys are deterministic ---
    println!("\n>> Primary key determinism");

    match (|| -> Result<(), TpmError> {
        let h1 = make_storage_primary(tpm)?;
        let h2 = make_storage_primary(tpm)?;

        let pub1 = tpm.ReadPublic(&h1)?;
        let pub2 = tpm.ReadPublic(&h2)?;

        if pub1.name == pub2.name {
            println!("Two primary keys from same template have identical names (as expected)");
        } else {
            println!("Warning: primary keys differ unexpectedly");
        }

        tpm.FlushContext(&h1)?;
        tpm.FlushContext(&h2)?;
        Ok(())
    })() {
        Ok(()) => {}
        Err(e) => println!("Primary key determinism test skipped ({})", e),
    }

    println!("Admin sample completed successfully");
    Ok(())
}

/// Demonstrates the PolicyTree abstraction for declarative policy composition.
/// This replaces the manual trial-session + command-by-command approach with
/// a composable tree that can compute digests and execute policies automatically.
fn policy_tree_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("PolicyTree Sample");

    let hash_alg = TPM_ALG_ID::SHA256;

    // -----------------------------------------------------------------------
    // 1) Simple PolicyTree: PolicyCommandCode restricting to HMAC_Start
    // -----------------------------------------------------------------------
    let tree = PolicyTree::new()
        .add(PolicyCommandCode::new(TPM_CC::HMAC_Start));

    // Compute digest in software (no TPM trial session needed)
    let sw_digest = tree.get_policy_digest(hash_alg)?;

    // Verify against a trial session on the TPM
    let trial = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyCommandCode(&session_handle(&trial), TPM_CC::HMAC_Start)?;
    let tpm_digest = tpm.PolicyGetDigest(&session_handle(&trial))?;
    tpm.FlushContext(&session_handle(&trial))?;

    assert_eq!(sw_digest, tpm_digest, "PolicyCommandCode: SW vs TPM digest mismatch");
    println!("PolicyTree digest (PolicyCommandCode) matches TPM trial: ");

    // -----------------------------------------------------------------------
    // 2) PolicyTree with multiple assertions chained
    // -----------------------------------------------------------------------
    let tree2 = PolicyTree::new()
        .add(PolicyLocality::new(TPMA_LOCALITY::LOC_ZERO))
        .add(PolicyCommandCode::new(TPM_CC::Sign));

    let sw_digest2 = tree2.get_policy_digest(hash_alg)?;

    let trial2 = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyLocality(&session_handle(&trial2), TPMA_LOCALITY::LOC_ZERO)?;
    tpm.PolicyCommandCode(&session_handle(&trial2), TPM_CC::Sign)?;
    let tpm_digest2 = tpm.PolicyGetDigest(&session_handle(&trial2))?;
    tpm.FlushContext(&session_handle(&trial2))?;

    assert_eq!(sw_digest2, tpm_digest2, "Chained policy: SW vs TPM digest mismatch");
    println!("PolicyTree digest (Locality + CommandCode) matches TPM trial: ");

    // -----------------------------------------------------------------------
    // 3) PolicyOR via PolicyTree
    // -----------------------------------------------------------------------
    // Branch 1: PolicyCommandCode(HMAC_Start)
    let branch1: Vec<Box<dyn policy::PolicyAssertion>> = vec![
        Box::new(PolicyCommandCode::new(TPM_CC::HMAC_Start)),
    ];
    // Branch 2: PolicyCommandCode(Sign)
    let branch2: Vec<Box<dyn policy::PolicyAssertion>> = vec![
        Box::new(PolicyCommandCode::new(TPM_CC::Sign)),
    ];

    let or_tree = PolicyTree::new()
        .add(PolicyOr::new(vec![branch1, branch2]));

    let sw_or_digest = or_tree.get_policy_digest(hash_alg)?;

    // Verify OR digest with TPM trial session
    let trial_b1 = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyCommandCode(&session_handle(&trial_b1), TPM_CC::HMAC_Start)?;
    let b1_digest = tpm.PolicyGetDigest(&session_handle(&trial_b1))?;
    tpm.FlushContext(&session_handle(&trial_b1))?;

    let trial_b2 = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyCommandCode(&session_handle(&trial_b2), TPM_CC::Sign)?;
    let b2_digest = tpm.PolicyGetDigest(&session_handle(&trial_b2))?;
    tpm.FlushContext(&session_handle(&trial_b2))?;

    let hash_list = vec![
        TPM2B_DIGEST { buffer: b1_digest },
        TPM2B_DIGEST { buffer: b2_digest },
    ];

    let trial_or = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyOR(&session_handle(&trial_or), &hash_list)?;
    let tpm_or_digest = tpm.PolicyGetDigest(&session_handle(&trial_or))?;
    tpm.FlushContext(&session_handle(&trial_or))?;

    assert_eq!(sw_or_digest, tpm_or_digest, "PolicyOR: SW vs TPM digest mismatch");
    println!("PolicyTree digest (PolicyOR) matches TPM trial: ");

    // -----------------------------------------------------------------------
    // 4) Execute a PolicyTree against a real policy session
    // -----------------------------------------------------------------------
    // Create an HMAC key with the simple PolicyCommandCode policy
    let hmac_key = make_hmac_primary_with_policy(tpm, &sw_digest, &[], hash_alg)?;

    // Execute the policy tree against a real session
    let policy_sess = tpm.start_auth_session(TPM_SE::POLICY, hash_alg)?;
    let policy_sess = tree.execute(tpm, policy_sess)?;

    let hmac_seq = tpm.with_session(policy_sess.clone()).HMAC_Start(&hmac_key, &vec![], hash_alg)?;
    println!("PolicyTree execute succeeded - HMAC_Start handle: {:?}", hmac_seq);
    tpm.FlushContext(&hmac_seq)?;
    tpm.FlushContext(&session_handle(&policy_sess))?;
    tpm.FlushContext(&hmac_key)?;

    // -----------------------------------------------------------------------
    // 5) PolicyPassword via PolicyTree  
    // -----------------------------------------------------------------------
    let pw_tree = PolicyTree::new()
        .add(PolicyPassword::new());

    let pw_digest = pw_tree.get_policy_digest(hash_alg)?;

    let trial_pw = tpm.start_auth_session(TPM_SE::TRIAL, hash_alg)?;
    tpm.PolicyPassword(&session_handle(&trial_pw))?;
    let tpm_pw_digest = tpm.PolicyGetDigest(&session_handle(&trial_pw))?;
    tpm.FlushContext(&session_handle(&trial_pw))?;

    assert_eq!(pw_digest, tpm_pw_digest, "PolicyPassword: SW vs TPM digest mismatch");
    println!("PolicyTree digest (PolicyPassword) matches TPM trial: ");

    println!("PolicyTree sample completed successfully");
    Ok(())
}

/// Demonstrates a salted (seeded) auth session. The salt is RSA-OAEP encrypted
/// to a storage primary's public key, providing protection even when authValues
/// are known or can be inferred.
fn seeded_session_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("SeededSession");

    // Create a storage primary to use as the salt-encryption key
    let salt_key = make_storage_primary(tpm)?;

    // Generate a random salt
    let salt = Crypto::get_random(20);
    println!("Salt ({} bytes): {:?}", salt.len(), &salt[..8]);

    // Start a salted HMAC session.
    // start_auth_session_ex will ReadPublic on the salt key, encrypt the salt
    // with RSA-OAEP (label "SECRET"), and derive the session key via KDFa.
    let sess = tpm.start_auth_session_ex(
        &salt_key,                                  // tpmKey for salt encryption
        &TPM_HANDLE::new(TPM_RH::NULL.get_value()), // no binding
        TPM_SE::HMAC,
        TPM_ALG_ID::SHA256,
        TPMA_SESSION::continueSession,
        TPMT_SYM_DEF::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
        &salt,
    )?;
    println!("Started salted HMAC session: {:?}", session_handle(&sess));

    // Use the salted session to create a child key under the storage primary
    let sign_parms = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
        &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::NULL, 0, TPM_ALG_ID::NULL),
        &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA { hashAlg: TPM_ALG_ID::SHA256 })),
        2048,
        65537,
    ));
    let in_pub = TPMT_PUBLIC::new(
        TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        &vec![],
        &Some(sign_parms),
        &Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default())),
    );

    let created = tpm.with_session(sess.clone()).Create(
        &salt_key, &TPMS_SENSITIVE_CREATE::default(), &in_pub, &vec![], &vec![],
    )?;
    let sess = tpm.last_session().unwrap_or(sess);
    println!("Created child key under salted session");

    // Load the child
    let child_handle = tpm.with_session(sess.clone()).Load(
        &salt_key, &created.outPrivate, &created.outPublic,
    )?;
    let sess = tpm.last_session().unwrap_or(sess);
    println!("Loaded child key: {:?}", child_handle);

    tpm.FlushContext(&child_handle)?;
    tpm.FlushContext(&session_handle(&sess))?;
    tpm.FlushContext(&salt_key)?;

    println!("SeededSession sample completed successfully");
    Ok(())
}

/// Demonstrates a bound auth session. A bound session is associated with a
/// specific TPM entity. When the session is used with that entity, the HMAC
/// calculation uses the entity's auth value in the session key derivation.
fn bound_session_sample(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("BoundSession");

    // Set owner auth to a known non-empty value
    let owner_auth: Vec<u8> = vec![0, 2, 1, 3, 5, 6];
    tpm.HierarchyChangeAuth(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &owner_auth)?;
    tpm.set_admin_auth(TPM_RH::OWNER, &owner_auth);

    // Run the actual test, then ALWAYS reset OWNER auth afterward
    let result = bound_session_inner(tpm, &owner_auth);

    // Always reset owner auth, even if the test failed
    tpm.allow_errors();
    let _ = tpm.HierarchyChangeAuth(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &vec![]);
    tpm.set_admin_auth(TPM_RH::OWNER, &vec![]);

    result
}

fn bound_session_inner(tpm: &mut Tpm2, owner_auth: &[u8]) -> Result<(), TpmError> {
    // Start a session bound to the owner handle
    let mut owner_handle = TPM_HANDLE::new(TPM_RH::OWNER.get_value());
    owner_handle.auth_value = owner_auth.to_vec();

    let sess = tpm.start_auth_session_ex(
        &TPM_HANDLE::new(TPM_RH::NULL.get_value()), // no salt
        &owner_handle,                                // bound to OWNER
        TPM_SE::HMAC,
        TPM_ALG_ID::SHA256,
        TPMA_SESSION::continueSession,
        TPMT_SYM_DEF::default(),
        &[],                                          // no salt
    )?;
    println!("Started bound session (bound to OWNER): {:?}", session_handle(&sess));

    // Use the bound session to define an NV index (owner-authorized operation)
    let nv_index: u32 = 0x01800099;
    let nv_handle = TPM_HANDLE::new(nv_index);

    // Clean up in case it exists from a previous run
    tpm.allow_errors();
    let _ = tpm.NV_UndefineSpace(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &nv_handle);

    let nv_pub = TPMS_NV_PUBLIC::new(
        &nv_handle,
        TPM_ALG_ID::SHA256,
        TPMA_NV::AUTHREAD | TPMA_NV::AUTHWRITE,
        &vec![],
        16,
    );

    // Define NV space using the bound session (bound to OWNER, same entity)
    let nv_auth: Vec<u8> = vec![5, 4, 3, 2, 1, 0];
    tpm.with_session(sess.clone()).NV_DefineSpace(
        &TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &nv_auth, &nv_pub,
    )?;
    let sess = tpm.last_session().unwrap_or(sess);
    println!("Defined NV index with bound session (same-entity binding)");

    // Read NV public to get the name
    let nv_info = tpm.NV_ReadPublic(&nv_handle)?;
    let mut nv_handle_with_auth = nv_handle.clone();
    nv_handle_with_auth.auth_value = nv_auth.clone();
    nv_handle_with_auth.set_name(&nv_info.nvName)?;

    // Write to NV using the bound session (different entity - the NV index)
    tpm.with_session(sess.clone()).NV_Write(
        &nv_handle_with_auth, &nv_handle_with_auth, &vec![0, 1, 2, 3], 0,
    )?;
    let sess = tpm.last_session().unwrap_or(sess);
    println!("Wrote to NV index with bound session (different-entity binding)");

    // Read back
    let read_data = tpm.with_session(sess.clone()).NV_Read(
        &nv_handle_with_auth, &nv_handle_with_auth, 4, 0,
    )?;
    let sess = tpm.last_session().unwrap_or(sess);
    println!("Read back NV data: {:?}", read_data);
    assert_eq!(read_data, vec![0, 1, 2, 3], "NV read/write mismatch");

    // Clean up NV and session
    tpm.allow_errors();
    let _ = tpm.NV_UndefineSpace(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &nv_handle);
    tpm.FlushContext(&session_handle(&sess))?;

    println!("BoundSession sample completed successfully");
    Ok(())
}

fn reset_da_lockout(tpm: &mut Tpm2) {
    tpm.allow_errors();
    let _ = tpm.DictionaryAttackLockReset(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()));
    if tpm.last_response_code() != TPM_RC::SUCCESS {
        if let Ok(da_info) = tpm.GetCapability(TPM_CAP::TPM_PROPERTIES, TPM_PT::LOCKOUT_COUNTER.get_value(), 4) {
            if let Some(TPMU_CAPABILITIES::tpmProperties(props)) = &da_info.capabilityData {
                for p in &props.tpmProperty {
                    match p.property {
                        TPM_PT::LOCKOUT_COUNTER => println!("DA failure count: {}", p.value),
                        TPM_PT::LOCKOUT_INTERVAL => println!("DA lockout interval: {} seconds", p.value),
                        TPM_PT::LOCKOUT_RECOVERY => println!("DA lockout recovery: {} seconds", p.value),
                        TPM_PT::MAX_AUTH_FAIL => println!("DA max auth fail: {}", p.value),
                        _ => {}
                    }
                }
            }
        }
        println!("Note: DictionaryAttackLockReset failed (rc={}), some auth-based samples may fail", tpm.last_response_code());
    } else {
        println!("DA lockout cleared successfully");
    }
}

fn recover_endorsement_hierarchy(tpm: &mut Tpm2) {
    let hash_alg = TPM_ALG_ID::SHA256;
    let endorsement_name = TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()).get_name().unwrap_or_default();
    let name_hash = Crypto::hash(hash_alg, &endorsement_name).unwrap_or_default();

    tpm.allow_errors();
    if let Ok(sess) = tpm.start_auth_session(TPM_SE::POLICY, hash_alg) {
        let _ = tpm.PolicyNameHash(&session_handle(&sess), &name_hash);
        let _ = tpm.with_session(sess.clone()).HierarchyChangeAuth(
            &TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()),
            &vec![],
        );
        let _ = tpm.FlushContext(&session_handle(&sess));
    }
    tpm.allow_errors();
    let _ = tpm.SetPrimaryPolicy(
        &TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()),
        &vec![],
        TPM_ALG_ID::NULL,
    );
}

fn recover_owner_hierarchy(tpm: &mut Tpm2) {
    let known_auths: Vec<Vec<u8>> = vec![
        Crypto::hash(TPM_ALG_ID::SHA1, b"passw0rd").unwrap_or_default(),
        vec![0, 2, 1, 3, 5, 6], // bound_session_sample
    ];
    for known_auth in &known_auths {
        tpm.set_admin_auth(TPM_RH::OWNER, known_auth);
        tpm.allow_errors();
        let _ = tpm.HierarchyChangeAuth(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()), &vec![]);
        if tpm.last_response_code() == TPM_RC::SUCCESS {
            println!("Recovered OWNER auth");
            break;
        }
    }
    tpm.set_admin_auth(TPM_RH::OWNER, &[]);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut device = Box::new(TpmTbsDevice::new());
    device.connect()?;
    let mut tpm = create_tpm_with_device(device);

    reset_da_lockout(&mut tpm);
    recover_endorsement_hierarchy(&mut tpm);
    recover_owner_hierarchy(&mut tpm);

    get_capabilities(&mut tpm)?;

    // ---- Samples ordered to match C++ RunAllSamples() ----

    rand_sample(&mut tpm)?;
    if let Err(e) = dictionary_attack_sample(&mut tpm) {
        print_error(&format!("dictionary_attack_sample failed (TPM may be in lockout): {}", e));
    }
    hash_sample(&mut tpm)?;
    if let Err(e) = hmac_sample(&mut tpm) {
        print_error(&format!("hmac_sample failed (may be DA lockout): {}", e));
    }
    pcr_sample(&mut tpm)?;
    if let Err(e) = policy_locality_sample(&mut tpm) {
        print_error(&format!("policy_locality_sample failed: {}", e));
    }
    // GetCapability already ran above
    if let Err(e) = nv_sample(&mut tpm) {
        print_error(&format!("nv_sample failed: {}", e));
    }
    if let Err(e) = primary_keys_sample(&mut tpm) {
        print_error(&format!("primary_keys_sample failed: {}", e));
    }
    if let Err(e) = auth_sessions_sample(&mut tpm) {
        print_error(&format!("auth_sessions_sample failed: {}", e));
    }
    if let Err(e) = async_sample(&mut tpm) {
        print_error(&format!("async_sample failed: {}", e));
    }
    if let Err(e) = policy_simplest_sample(&mut tpm) {
        print_error(&format!("policy_simplest_sample failed: {}", e));
    }
    if let Err(e) = policy_pcr_sample(&mut tpm) {
        print_error(&format!("policy_pcr_sample failed: {}", e));
    }
    if let Err(e) = child_keys_sample(&mut tpm) {
        print_error(&format!("child_keys_sample failed (likely TBS-blocked ContextSave): {}", e));
    }
    if let Err(e) = policy_or_sample(&mut tpm) {
        print_error(&format!("policy_or_sample failed: {}", e));
    }
    counter_timer_sample(&mut tpm)?;
    if let Err(e) = attestation(&mut tpm) {
        print_error(&format!("attestation failed: {}", e));
    }
    if let Err(e) = admin_sample(&mut tpm) {
        print_error(&format!("admin_sample failed: {}", e));
    }
    if let Err(e) = policy_cphash_sample(&mut tpm) {
        print_error(&format!("policy_cphash_sample failed: {}", e));
    }
    if let Err(e) = policy_counter_timer_sample(&mut tpm) {
        print_error(&format!("policy_counter_timer_sample failed: {}", e));
    }
    if let Err(e) = policy_with_passwords_sample(&mut tpm) {
        print_error(&format!("policy_with_passwords_sample failed: {}", e));
    }
    if let Err(e) = unseal_sample(&mut tpm) {
        print_error(&format!("unseal_sample failed: {}", e));
    }
    // Serializer - N/A for Rust
    if let Err(e) = session_encryption_sample(&mut tpm) {
        print_error(&format!("session_encryption_sample failed: {}", e));
    }
    if let Err(e) = import_duplicate_sample(&mut tpm) {
        print_error(&format!("import_duplicate_sample failed: {}", e));
    }
    if let Err(e) = misc_admin_sample(&mut tpm) {
        print_error(&format!("misc_admin_sample failed: {}", e));
    }
    if let Err(e) = rsa_encrypt_decrypt_sample(&mut tpm) {
        print_error(&format!("rsa_encrypt_decrypt_sample failed: {}", e));
    }
    if let Err(e) = audit_sample(&mut tpm) {
        print_error(&format!("audit_sample failed: {}", e));
    }
    if let Err(e) = activate_credentials(&mut tpm) {
        print_error(&format!("activate_credentials failed: {}", e));
    }
    if let Err(e) = software_keys_sample(&mut tpm) {
        print_error(&format!("software_keys_sample failed: {}", e));
    }
    if let Err(e) = policy_signed_sample(&mut tpm) {
        print_error(&format!("policy_signed_sample failed: {}", e));
    }
    if let Err(e) = policy_authorize_sample(&mut tpm) {
        print_error(&format!("policy_authorize_sample failed: {}", e));
    }
    if let Err(e) = policy_secret_sample(&mut tpm) {
        print_error(&format!("policy_secret_sample failed: {}", e));
    }
    if let Err(e) = encrypt_decrypt_sample(&mut tpm) {
        print_error(&format!("encrypt_decrypt_sample failed (likely TBS-blocked EncryptDecrypt): {}", e));
    }
    if let Err(e) = policy_with_passwords_sample(&mut tpm) {
        print_error(&format!("policy_with_passwords_sample (2nd run) failed: {}", e));
    }
    // SeededSession - not yet implemented (needs RSA-encrypt salt)
    if let Err(e) = policy_nv_sample(&mut tpm) {
        print_error(&format!("policy_nv_sample failed: {}", e));
    }
    if let Err(e) = policy_name_hash_sample(&mut tpm) {
        print_error(&format!("policy_name_hash_sample failed: {}", e));
    }
    if let Err(e) = rewrap_sample(&mut tpm) {
        print_error(&format!("rewrap_sample failed: {}", e));
    }
    if let Err(e) = policy_tree_sample(&mut tpm) {
        print_error(&format!("policy_tree_sample failed: {}", e));
    }
    if let Err(e) = seeded_session_sample(&mut tpm) {
        print_error(&format!("seeded_session_sample failed: {}", e));
    }
    if let Err(e) = bound_session_sample(&mut tpm) {
        print_error(&format!("bound_session_sample failed: {}", e));
    }
    // NVX - not yet implemented (needs Platform auth / simulator)

    announce(
        "************************* 🦀🦀🦀 Generated by Tss.Rust 🦀🦀🦀 *************************",
    );

    Ok(())
}
