use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct Config {
    #[structopt(short, long, default_value = "27228")]
    pub port: u16,

    #[structopt(env, default_value = "tracing=info,warp=debug")]
    pub rust_log: String,
}

pub fn parse() -> Config {
    Config::from_args()
}
