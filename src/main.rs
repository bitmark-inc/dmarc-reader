// main.rs

use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{load_yaml, values_t, App};
use flate2::read::GzDecoder;
use postgres::params::{ConnectParams, Host};
use postgres::{Connection, TlsMode};
use serde_derive::{Deserialize, Serialize};
use serde_xml_rs::from_reader;
use std::clone::Clone;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::io::{Read, Seek};
use zip::read::ZipFile;
use zip::result::ZipResult;
use zip::ZipArchive;

//#[macro_use]
use postgres::to_sql_checked;
//#[macro_use]
use postgres_derive::{FromSql, ToSql};

mod config;

// allow use of '?' to quick return error
type MyResult<T> = Result<T, Box<Error>>;

// XML schema derived from: https://tools.ietf.org/html/rfc7489

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct DateRange {
    begin: i64, // specified in seconds since epoch
    end: i64,   // specified in seconds since epoch
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ReportMetadata {
    org_name: String,
    email: String,
    #[serde(default)]
    extra_contact_info: String,
    report_id: String,
    date_range: DateRange,
}

// AlignmentType = "r", "s"  // relaxed or strict
#[derive(Clone, Copy, Debug, ToSql, FromSql, Serialize, Deserialize, PartialEq)]
#[postgres(name = "alignment_type")]
enum AlignmentType {
    #[postgres(name = "r")]
    #[serde(rename = "r")]
    Relaxed,
    #[postgres(name = "s")]
    #[serde(rename = "s")]
    Strict,
}

// DispositionType = "none", "quarantine", "reject"
#[derive(Clone, Copy, Debug, ToSql, FromSql, Serialize, Deserialize, PartialEq)]
#[postgres(name = "disposition_type")]
enum DispositionType {
    #[postgres(name = "none")]
    #[serde(rename = "none")]
    None,
    #[postgres(name = "quarantine")]
    #[serde(rename = "quarantine")]
    Quarantine,
    #[postgres(name = "reject")]
    #[serde(rename = "reject")]
    Reject,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PolicyPublished {
    domain: String,
    #[serde(default)]
    adkim: String, // AlignmentType    dkim alignment
    #[serde(default)]
    aspf: String, // AlignmentType    spf alignment
    p: String, // DispositionType  domain policy
    #[serde(default)]
    sp: String, // DispositionType  subdomain policy
    pct: u32,  // 0..100           percentage
    #[serde(default)]
    fo: String, // Failure reporting options in effect
}

// DMARCResultType = "pass", "fail"
#[derive(Clone, Copy, Debug, ToSql, FromSql, Serialize, Deserialize, PartialEq)]
#[postgres(name = "dmarc_result_type")]
enum DMARCResultType {
    #[postgres(name = "pass")]
    #[serde(rename = "pass")]
    Pass,
    #[postgres(name = "fail")]
    #[serde(rename = "fail")]
    Fail,
}

// PolicyOverrideType = "forwarded", "sampled_out", "trusted_forwarder",
//                      "mailing_list", "local_policy", "other"
#[derive(Clone, Copy, Debug, ToSql, FromSql, Serialize, Deserialize, PartialEq)]
#[postgres(name = "policy_override_type")]
enum PolicyOverrideType {
    #[postgres(name = "forwarded")]
    #[serde(rename = "forwarded")]
    Forwarded,
    #[postgres(name = "sampled_out")]
    #[serde(rename = "sampled_out")]
    SampledOut,
    #[postgres(name = "trusted_forwarder")]
    #[serde(rename = "trusted_forwarder")]
    TrustedForwarder,
    #[postgres(name = "mailing_list")]
    #[serde(rename = "mailing_list")]
    MailingList,
    #[postgres(name = "local_policy")]
    #[serde(rename = "local_policy")]
    LocalPolicy,
    #[postgres(name = "other")]
    #[serde(rename = "other")]
    Other,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PolicyOverrideReason {
    #[serde(rename = "type")]
    type_: PolicyOverrideType,
    comment: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PolicyEvaluated {
    disposition: DispositionType,
    dkim: DMARCResultType,
    spf: DMARCResultType,
    //    #[serde(default)]
    reason: Option<PolicyOverrideReason>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Row {
    source_ip: String,
    count: u32,
    policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Identifier {
    #[serde(default)]
    envelope_to: String,
    #[serde(default)]
    envelope_from: String,
    header_from: String,
}

// DKIMResultType = "none", "pass", "fail", "policy",
//                  "neutral", "temperror", "permerror
#[derive(Clone, Copy, Debug, ToSql, FromSql, Serialize, Deserialize, PartialEq)]
#[postgres(name = "dkim_result_type")]
enum DKIMResultType {
    #[postgres(name = "none")]
    #[serde(rename = "none")]
    None,
    #[postgres(name = "pass")]
    #[serde(rename = "pass")]
    Pass,
    #[postgres(name = "fail")]
    #[serde(rename = "fail")]
    Fail,
    #[postgres(name = "policy")]
    #[serde(rename = "policy")]
    Policy,
    #[postgres(name = "neutral")]
    #[serde(rename = "neutral")]
    Neutral,
    #[postgres(name = "temperror")]
    #[serde(rename = "temperror")]
    TempError,
    #[postgres(name = "permerror")]
    #[serde(rename = "permerror")]
    PermError,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct DKIMAuthResult {
    domain: String, // The "d=" parameter in the signature
    #[serde(default)]
    selector: String, // The "s=" parameter in the signature
    result: DKIMResultType,
    #[serde(default)]
    human_result: String, // Any extra information
}

// SPFDomainScope = "helo", "mfrom"
#[derive(Clone, Copy, Debug, ToSql, FromSql, Serialize, Deserialize, PartialEq)]
#[postgres(name = "spf_domain_scope_type")]
enum SPFDomainScope {
    #[postgres(name = "helo")]
    #[serde(rename = "helo")]
    Helo,
    #[postgres(name = "mfrom")]
    #[serde(rename = "mfrom")]
    MFrom,
}

// SPFResultType = "none", "neutral", "pass", "fail", "softfail",
//                 "temperror"/"unknown",
//                 "permerror"/"error"
#[derive(Clone, Copy, Debug, ToSql, FromSql, Serialize, Deserialize, PartialEq)]
#[postgres(name = "spf_result_type")]
enum SPFResultType {
    #[postgres(name = "none")]
    #[serde(rename = "none")]
    None,
    #[postgres(name = "neutral")]
    #[serde(rename = "neutral")]
    Neutral,
    #[postgres(name = "pass")]
    #[serde(rename = "pass")]
    Pass,
    #[postgres(name = "fail")]
    #[serde(rename = "fail")]
    Fail,
    #[postgres(name = "softfail")]
    #[serde(rename = "softfail")]
    SoftFail,
    #[postgres(name = "temperror")]
    #[serde(rename = "temperror")]
    TempError,
    #[postgres(name = "permerror")]
    #[serde(rename = "permerror")]
    PermError,
    #[postgres(name = "unknown")]
    #[serde(rename = "unknown")]
    Unknown,
    #[postgres(name = "error")]
    #[serde(rename = "error")]
    Error,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct SPFAuthResult {
    domain: String,
    scope: Option<SPFDomainScope>,
    result: SPFResultType,
    #[serde(default)]
    selector: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct AuthResult {
    #[serde(default)] // allows for empty vector
    dkim: Vec<DKIMAuthResult>,
    spf: Vec<SPFAuthResult>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Record {
    row: Row,
    identifiers: Identifier,
    auth_results: AuthResult,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Feedback {
    report_metadata: ReportMetadata,
    policy_published: PolicyPublished,
    record: Vec<Record>,
}

// main
// ----

fn main() -> MyResult<()> {
    // The YAML file is found relative to the current file, similar to how modules are found
    let yaml = load_yaml!("cli.yaml");
    let matches = App::from_yaml(yaml).get_matches();

    let debug = matches.is_present("debug");

    let c = matches.value_of("config").unwrap();
    let db = config::read(c, debug)?;

    if debug {
        println!("Value for config: {}", c);
        println!("Value for database: {:?}", db);
    }

    let mut p = ConnectParams::builder();
    p.user(&db.user, Some(&db.password)).database(&db.database);

    let params = if db.host.starts_with("/") {
        p.build(Host::Unix(std::path::Path::new(&db.host).to_path_buf()))
    } else {
        match db.port {
            Some(n) => p.port(n),
            None => &mut p,
        }
        .build(Host::Tcp(db.host))
    };

    let mut conn = Connection::connect(params, TlsMode::None)?;

    if debug {
        match matches.occurrences_of("verbose") {
            0 => println!("verbose mode is off"),
            1 => println!("verbose mode is low"),
            2 => println!("verbose mode is on"),
            3 | _ => println!("maximum verbosity"),
        }
    }

    // iterate through all values
    for f in values_t!(matches, "FILES", String).unwrap_or_else(|e| e.exit()) {
        println!("file: {}", f);
        if f.ends_with(".xml") || f.ends_with(".xml.gz") {
            read_file(&f, &mut conn, debug)?;
        } else if f.ends_with(".zip") {
            process_zip(&f, &mut conn, debug)?;
        } else {
            println!("ignoring: {}", f);
        }
    }
    Ok(())
}

fn read_file(filename: &str, conn: &mut postgres::Connection, debug: bool) -> MyResult<()> {
    let compressed = filename.ends_with(".gz");
    let input = File::open(filename)?;
    process_file(input, compressed, conn, debug)
}

fn process_file<T>(
    input: T,
    compressed: bool,
    conn: &mut postgres::Connection,
    debug: bool,
) -> MyResult<()>
where
    T: Read, // + Seek,
{
    let feedback: Feedback = if compressed {
        let z = GzDecoder::new(input);
        from_reader(z)?
    } else {
        let b = BufReader::new(input);
        from_reader(b)?
    };

    if debug {
        println!("{:?}", feedback);
    }
    insert_report(&feedback, conn);
    Ok(())
}

fn browse_zip_archive<T, F, U>(buf: &mut T, mut browse_func: F) -> ZipResult<Vec<U>>
where
    T: Read + Seek,
    F: FnMut(&mut ZipFile) -> ZipResult<U>,
{
    let mut archive = ZipArchive::new(buf)?;
    (0..archive.len())
        .map(|i| {
            archive
                .by_index(i)
                .and_then(|mut file| browse_func(&mut file))
        })
        .collect()
}

fn process_zip(name: &str, conn: &mut postgres::Connection, debug: bool) -> MyResult<()> {
    let mut file = File::open(name)?;
    let _ = browse_zip_archive(&mut file, |f| {
        if debug {
            let filename = f.name();
            println!("file: {}", filename);
            // let mut contents = String::new();
            // f.read_to_string(&mut contents).unwrap();
            // println!("{}", contents);
        }

        let compressed = f.name().ends_with(".xml.gz");
        let b = BufReader::new(f);
        process_file(b, compressed, conn, debug).unwrap();

        // Ok(format!(
        //     "{}: {} -> {}",
        //     filename, //f.name(),
        //     f.size(),
        //     f.compressed_size()
        // ))
        //Ok(f.name().to_string())
        Ok(())
    });

    Ok(())
}

fn insert_report(feedback: &Feedback, conn: &mut postgres::Connection) {
    let metadata = &feedback.report_metadata;
    let policy = &feedback.policy_published;

    let dt_begin = DateTime::<Utc>::from_utc(
        NaiveDateTime::from_timestamp(metadata.date_range.begin, 0),
        Utc,
    )
    .to_rfc3339();
    let dt_end = DateTime::<Utc>::from_utc(
        NaiveDateTime::from_timestamp(metadata.date_range.end, 0),
        Utc,
    )
    .to_rfc3339();

    // if debug {
    //     println!("dated: {} - {}", dt_begin, dt_end);
    //     println!("pct: {}", policy.pct);
    // }

    let pct = policy.pct as i64;

    conn.execute(
        r##"INSERT INTO dmarc.report
  (report_begin_date,
   report_end_date,
   report_domain,
   report_org_name,
   report_id,
   report_email,
   report_policy_adkim,
   report_policy_aspf,
   report_policy_p,
   report_policy_sp,
   report_policy_pct)
 VALUES (to_timestamp($1,'YYYY-MM-DD"T"HH24:MI:SS'),
         to_timestamp($2,'YYYY-MM-DD"T"HH24:MI:SS'),
         $3,$4,$5,$6,$7,$8,$9,$10,$11);"##,
        &[
            &dt_begin, // metadata.date_range.begin,
            &dt_end,   // metadata.date_range.end,
            &policy.domain,
            &metadata.org_name,
            &metadata.report_id,
            &metadata.email,
            &policy.adkim,
            &policy.aspf,
            &policy.p,
            &policy.sp,
            &pct,
        ],
    )
    .expect("insert report failed");

    for item in &feedback.record {
        let (dd, dr) = if item.auth_results.dkim.len() > 0 {
            (
                item.auth_results.dkim[0].domain.clone(),
                item.auth_results.dkim[0].result,
            )
        } else {
            let d = "*undef*".to_string();
            let r = DKIMResultType::None;
            (d.clone(), r)
        };
        let (sd, sr) = if item.auth_results.spf.len() > 0 {
            (
                item.auth_results.spf[0].domain.clone(),
                item.auth_results.spf[0].result,
            )
        } else {
            let d = "*undef*".to_string();
            let r = SPFResultType::None;
            (d.clone(), r)
        };

        let reason = match &item.row.policy_evaluated.reason {
            Some(r) => r.comment.clone(),
            None => "-".to_string(),
        };

        let count = item.row.count as i64;

        conn.execute(
            r##"
INSERT INTO dmarc.item
  (item_report_id,
  item_ip,
  item_count,
  item_disposition,
  item_dkim_domain,
  item_dkim_result,
  item_policy_dkim,
  item_spf_domain,
  item_spf_result,
  item_policy_spf,
  item_reason,
  item_header_from)
 VALUES ($1,$2,$3,
         cast($4 AS disposition_type),
         $5,$6,$7,$8,$9,
         $10,$11,$12);
"##,
            &[
                &metadata.report_id,
                &item.row.source_ip,
                &count,
                &item.row.policy_evaluated.disposition,
                &dd, // item.auth_results.dkim[0].domain,
                &dr, // item.auth_results.dkim[0].result,
                &item.row.policy_evaluated.dkim,
                &sd, // item.auth_results.spf.domain,
                &sr, //item.auth_results.spf.result,
                &item.row.policy_evaluated.spf,
                &reason,
                &item.identifiers.header_from,
            ],
        )
        .expect("insert item failed");
    }
}
