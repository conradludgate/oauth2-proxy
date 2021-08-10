use metrics::histogram;
use rocket::{Request, Data, Response};
use rocket::fairing::{Fairing, Info, Kind};

pub struct RouteMetrics;
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

        let status = response.status().code;
        let route = request.route().unwrap();
        let method = route.method;
        let name = route.name.clone().unwrap();

        histogram!("oauth2_proxy_route_durations", duration, "method" => method.to_string(), "route" => name, "status" => status.to_string());
    }
}
