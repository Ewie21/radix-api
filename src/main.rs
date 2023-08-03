#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;
use std::{
    env, 
    collections::HashMap
};
use lettre::{
    message::header::ContentType,
    transport::smtp::{
        authentication::{Credentials, Mechanism},
        PoolConfig
    },
    Message, 
    SmtpTransport,
    Transport,

};
use rocket::{
    http::Status, 
    response::status,
    form::Form,
    Rocket,
    Build
};
use serde_json::json;
use serde_with::serde_as;

#[derive(Debug)]
enum RadixError {
    EmailSendingError(lettre::transport::smtp::Error),
    EmailBuildingError(lettre::error::Error)
}

fn email(subject: String, body: String, to: String) -> Result<(), RadixError> {
    //let _listen: String = env::var("LISTEN").unwrap();
    let smtp_user: String = env::var("SMTP_USER").expect("a valid email");
    let smtp_pass: String = env::var("SMTP_PASS").expect("the correct email password");
    let smtp_host: String = env::var("SMTP_HOST").expect("a valid smtp host");
    let creds = Credentials::new(smtp_user.clone(), smtp_pass.clone());

    println!("subject: {}\nbody: {}", subject, body);
    println!("user: {}", smtp_user);
    println!("host: {}", smtp_host);
    println!("password: {}", smtp_pass);

    let mailer = 
        SmtpTransport::relay(&(smtp_host + ":587")).expect("a valid smtp host")
        .credentials(creds)
        .authentication(vec![Mechanism::Plain])
        .pool_config(PoolConfig::new().max_size(20))
        .build();
    //let mailer = SmtpTransport::unencrypted_localhost();
    let email = 
        match Message::builder()
        .from("<noreply@radixproject.org".parse().expect("properly formatted radix project email")) 
        .to(to.parse().expect("properly formatted radix project email"))
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body) {
            Ok(m) => m,
            Err(e) => return Err(RadixError::EmailBuildingError(e))
        };
    match mailer.send(&email) { // Ok variant is returning but I'm not getting the email in my inbox
        Ok(_) => {
            println!("Email Sent!");
            Ok(())
        },
        Err(e) => {
            println!("Email sending Error: {:?}", e);
            Err(RadixError::EmailSendingError(e))
        }
    }
}

#[serde_as]
#[derive(FromForm, rocket::serde::Deserialize, serde::Serialize)]
struct RadixForm {
    email: String,
    name: String,
    role: String,
    summary: String,
    description: String,
    services: String,
    why: String,
    adopters: String,
    code: String,
    info: String
}

impl RadixForm {
    fn to_hashmap(&self) -> HashMap<&'static str, String> {
        HashMap::from([
            ("email", self.email.clone()),
            ("name", self.name.clone()),
            ("role", self.role.clone()),
            ("summary", self.summary.clone()),
            ("description", self.description.clone()),
            ("services", self.services.clone()),
            ("why", self.why.clone()),
            ("adopters", self.adopters.clone()),
            ("code", self.code.clone()),
            ("info", self.info.clone())
        ])
    }
}

#[get("/health")]
fn health() -> status::Custom<&'static str> {
    status::Custom(Status::Ok, "ok")
}

#[post("/form", data="<form_input>")]
fn form(form_input: Form<RadixForm>) -> status::Custom<serde_json::Value> {
    let body: HashMap<&str, String> = form_input.to_hashmap();
    let name = body.get("name").expect("name was explicitly inserted");
    println!("testing {}", name);
    let mut out = format!("Received submission for {} form\n\n", name);
    for (k, v) in &body {
        out += &format!("{}:\n{}\n\n", k, v);
    }
    let to = "<info@radixproject.org>".to_string();

    if let Err(err) = email(name.to_string() + " form submission", out, to) {
        println!("{:?}", err);
        return status::Custom(
            Status::InternalServerError,
            json!({
                "error": true,
                "message": "Invalid JSON Body".to_string()
            }),
        );
    }

    status::Custom(
        Status::Ok,
        json!({
            "error": false,
            "message": "ok"
        }),
    )
}

#[launch]
fn launch() -> Rocket<Build> {
    rocket::build()
    .mount("/", routes![health, form])
}

#[cfg(test)]
mod test {
    use lettre::{
        transport::smtp::{
            authentication::{Credentials, Mechanism},
            PoolConfig
        },
        Message, 
        SmtpTransport,
        Transport,
    };
    use rocket::http::{
        ContentType, 
        Status
    };
    use super::rocket;
    use crate::{
        launch,
        RadixForm
    };
    use rocket::local::blocking::Client;

    #[test]
    fn lettre_test() {
        let creds = Credentials::new("elocolburn@comcast.net".to_owned(), "2008Ewie21".to_owned());
        let mailer = 
            SmtpTransport::relay(&("smtp.comcast.net".to_owned() + ":587")).expect("a valid host")
            .credentials(creds)
            .authentication(vec![Mechanism::Plain])
            .pool_config(PoolConfig::new().max_size(20))
            .build();
        let email = 
            Message::builder()
            .from("Elo <elocolburn@comcast.net>".parse().unwrap())
            .reply_to("Elo <elocolburn@comcast.net>".parse().unwrap())
            .to("EloRadix <elo@radixproject.org>".parse().unwrap())
            .subject("Test")
            .body(String::from("Test successful")).unwrap();
        let result = mailer.send(&email);
        assert!(result.is_ok(), "Failed to send email, {:?}", result.err());
    }


    #[test]
    fn health() {
        let client = Client::tracked(launch()).unwrap();
        let req = client.get("/health");
        let res= req.dispatch();
        assert_eq!(res.status(), Status::Ok);
    }

    #[test]
    fn form() {
        let client = Client::tracked(launch()).expect("a valid rocket instance");
        let form_data = RadixForm {
            email: "elocolburn@comcast.net".to_string(),
            name: "EloTesting".to_string(),
            role: "tester".to_string(),
            summary: "This is a test".to_string(),
            description: "Still a test".to_string(),
            services: "testing".to_string(),
            why: "for testing purposes".to_string(),
            adopters: "nonejusttesting".to_string(),
            code: "test(not a url lol)".to_string(),
            info: "n/a-test".to_string()
        };
        let req = 
            client.post("/form")
            .header(ContentType::Form)
            .body(
                match serde_urlencoded::to_string(&form_data) {
                    Err(e) => panic!("\nError: {}\n", e),
                    Ok(val) => val,
            });
        let res= req.dispatch();
        //println!("{:?}", res.into_string().unwrap());
        assert_eq!(res.status(), Status::Ok);
    }
}
