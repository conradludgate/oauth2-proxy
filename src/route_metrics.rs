use metrics::histogram;
use rocket::{Request, Data, Response};
use rocket::fairing::{Fairing, Info, Kind};

struct RouteMetrics;
struct RouteInstance(std::time::Instant);

fn time() -> RouteInstance {
    RouteInstance(std::time::Instant::now())
}

#[rocket::async_trait]
impl Fairing for RouteMetrics {
    fn info(&self) -> Info {
        Info {
            name: "Route Metrics",
            kind: Kind::Request | Kind::Response
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        request.local_cache(time);
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let start = request.local_cache(time);
        let duration = time().0.duration_since(start.0.to_owned());

        histogram!("oauth2_proxy_route_durations", duration, "route" => request.route().unwrap().to_string(), "status" => response.status().to_string());
    }
}
