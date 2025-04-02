use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::route::{Handler, Outcome};
use rocket::{Data, Request, Response};

#[derive(Clone)]
pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "CORS headers",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _req: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "PUT, GET, HEAD, DELETE, OPTIONS, POST, PATCH",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[rocket::async_trait]
impl Handler for CORS {
    async fn handle<'r>(&self, _request: &'r Request<'_>, _data: Data<'r>) -> Outcome<'r> {
        Outcome::Success(Response::new())
    }
}
