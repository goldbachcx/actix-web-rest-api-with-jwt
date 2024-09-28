use std::path::PathBuf;
use actix_files::{Files, NamedFile};
use actix_web::{http, web};
use dotenv::Error;
use log::info;

use crate::api::*;

pub fn config_services(cfg: &mut web::ServiceConfig) {
    info!("Configuring routes...");
    cfg.service(
        web::scope("/api")
            .service(ping_controller::ping)
            .service(
                web::scope("/auth")
                    .service(
                        web::resource("/signup").route(web::post().to(account_controller::signup)),
                    )
                    .service(
                        web::resource("/login").route(web::post().to(account_controller::login)),
                    )
                    .service(
                        web::resource("/logout").route(web::post().to(account_controller::logout)),
                    )
                    .service(
                        web::resource("/me").route(web::get().to(account_controller::me)),
                    ),
            )
            .service(
                web::scope("/address-book")
                    .service(
                        web::resource("")
                            .route(web::get().to(address_book_controller::find_all))
                            .route(web::post().to(address_book_controller::insert)),
                    )
                    .service(
                        web::resource("/{id}")
                            .route(web::get().to(address_book_controller::find_by_id))
                            .route(web::put().to(address_book_controller::update))
                            .route(web::delete().to(address_book_controller::delete)),
                    )
                    .service(
                        web::resource("/filter")
                            .route(web::get().to(address_book_controller::filter)),
                    ),
            ),
    );
    cfg.service(Files::new("/static", "./resources").use_last_modified(true)  // 启用 Last-Modified 头
                    .use_etag(true)           // 启用 ETag 头
                    .prefer_utf8(true)        // 使用 UTF-8
    );
}