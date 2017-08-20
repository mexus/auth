use rocket::request::FlashMessage;
use std::convert::From;

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct FlashMsg {
    name: String,
    message: String,
}

impl From<FlashMessage> for FlashMsg {
    fn from(f: FlashMessage) -> Self {
        FlashMsg {
            name: match f.name() {
                "success" => "success",
                "warning" => "warning",
                "error" => "danger",
                _ => "primary",
            }.into(),
            message: f.msg().into(),
        }
    }
}
