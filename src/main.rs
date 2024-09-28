#![allow(unused_must_use)]

use std::default::Default;
use std::{env, io};

use actix_cors::Cors;
use actix_web::dev::Service;
use actix_web::web;
use actix_web::{http, App, HttpServer};
use futures::FutureExt;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

mod api;
mod config;
mod constants;
mod error;
mod middleware;
mod models;
mod schema;
mod services;
mod utils;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    dotenv::dotenv().expect("Failed to read .env file");
    env::set_var("RUST_LOG", "actix_web=debug");
    env_logger::init();

    let app_host = env::var("APP_HOST").expect("APP_HOST not found.");
    let http_port = env::var("HTTP_PORT").expect("HTTP_PORT not found.");
    let https_port = env::var("HTTPS_PORT").expect("HTTPS_PORT not found.");
    let allowed_origin = env::var("ALLOWED_ORIGIN").expect("ALLOWED_ORIGIN not found.");
    let http_url = format!("{}:{}", &app_host, &http_port);
    let https_url = format!("{}:{}", &app_host, &https_port);
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not found.");

    let pool = config::db::init_db_pool(&db_url);
    config::db::run_migration(&mut pool.get().unwrap());

    // 创建 SSL/TLS 接受器
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file("security/private.key", SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file("security/cert.pem").unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default() // allowed_origin return access-control-allow-origin: * by default
                    .allowed_origin(&format!("{}:{}", "http://127.0.0.1", &http_port))
                    .allowed_origin(&format!("{}:{}", "http://localhost", &https_port))
                    .allowed_origin(&allowed_origin)
                    .send_wildcard()
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                    .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                    .allowed_header(http::header::CONTENT_TYPE)
                    .max_age(3600),
            )
            .app_data(web::Data::new(pool.clone()))
            .wrap(actix_web::middleware::Logger::default())
            .wrap(crate::middleware::auth_middleware::Authentication) // Comment this line if you want to integrate with yew-address-book-frontend
            .wrap_fn(|req, srv| srv.call(req).map(|res| res))
            .configure(config::app::config_services)
    })
        .bind(&http_url)?
        .bind_openssl(&https_url, builder)?  // HTTPS 监听端口
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use actix_cors::Cors;
    use actix_web::dev::Service;
    use actix_web::web;
    use actix_web::{http, App, HttpServer};
    use futures::FutureExt;
    use testcontainers::clients;
    use testcontainers::images::postgres::Postgres;

    use crate::config;

    #[actix_web::test]
    async fn test_startup_ok() {
        let docker = clients::Cli::default();
        let postgres = docker.run(Postgres::default());
        let pool = config::db::init_db_pool(
            format!(
                "postgres://postgres:postgres@127.0.0.1:{}/postgres",
                postgres.get_host_port_ipv4(5432)
            )
                .as_str(),
        );
        config::db::run_migration(&mut pool.get().unwrap());

        HttpServer::new(move || {
            App::new()
                .wrap(
                    Cors::default() // allowed_origin return access-control-allow-origin: * by default
                        // .allowed_origin("http://127.0.0.1:8080")
                        .send_wildcard()
                        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                        .allowed_header(http::header::CONTENT_TYPE)
                        .max_age(3600),
                )
                .app_data(web::Data::new(pool.clone()))
                .wrap(actix_web::middleware::Logger::default())
                .wrap(crate::middleware::auth_middleware::Authentication)
                .wrap_fn(|req, srv| srv.call(req).map(|res| res))
                .configure(config::app::config_services)
        })
            .bind("localhost:8000".to_string())
            .unwrap()
            .run();

        assert_eq!(true, true);
    }

    #[actix_web::test]
    async fn test_startup_without_auth_middleware_ok() {
        let docker = clients::Cli::default();
        let postgres = docker.run(Postgres::default());
        let pool = config::db::init_db_pool(
            format!(
                "postgres://postgres:postgres@127.0.0.1:{}/postgres",
                postgres.get_host_port_ipv4(5432)
            )
                .as_str(),
        );
        config::db::run_migration(&mut pool.get().unwrap());

        HttpServer::new(move || {
            App::new()
                .wrap(
                    Cors::default() // allowed_origin return access-control-allow-origin: * by default
                        // .allowed_origin("http://127.0.0.1:8080")
                        .send_wildcard()
                        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                        .allowed_header(http::header::CONTENT_TYPE)
                        .max_age(3600),
                )
                .app_data(web::Data::new(pool.clone()))
                .wrap(actix_web::middleware::Logger::default())
                .wrap_fn(|req, srv| srv.call(req).map(|res| res))
                .configure(config::app::config_services)
        })
            .bind("localhost:8001".to_string())
            .unwrap()
            .run();

        assert_eq!(true, true);
    }
}
