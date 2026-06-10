mod types;
use types::{BannedClient, BlockHistory};
use raylib::prelude::*;
use chrono::{Utc, Duration};
use std::net::Ipv4Addr;

fn main() {
    let (mut rl, thread) = raylib::init()
        .size(1280, 720)
        .title("Aincrad-XDP // Dynamic Firewall GUI")
        .vsync()
        .build();

    let mut history = BlockHistory::new();
    let mut bg_packet_x = 0.0;
    
    let mut banned_ips = vec![
        BannedClient {
            ip: Ipv4Addr::new(192, 168, 0, 15),
            ban_until: Utc::now() + Duration::seconds(10),
            total_duration: Duration::seconds(10),
        },
        BannedClient {
            ip: Ipv4Addr::new(10, 0, 0, 22),
            ban_until: Utc::now() + Duration::seconds(30),
            total_duration: Duration::seconds(30),
        },
        BannedClient {
            ip: Ipv4Addr::new(172, 16, 254, 1),
            ban_until: Utc::now() + Duration::seconds(60),
            total_duration: Duration::seconds(60),
        },
    ];

    history.push_block();
    history.push_block();
    history.push_block();

    while !rl.window_should_close() {
        let delta_time = rl.get_frame_time();
        history.clean_expired_blocks();

        bg_packet_x += 180.0 * delta_time;
        if bg_packet_x > 1280.0 { bg_packet_x = -50.0; }

        banned_ips.retain(|client| Utc::now() < client.ban_until);

        let mut d = rl.begin_drawing(&thread);
        d.clear_background(Color::new(26, 26, 26, 255)); // Grafite escuro

        for y in (0..720).step_by(4) {
            d.draw_line(0, y, 1280, y, Color::new(0, 0, 0, 20));
        }

        d.draw_rectangle(bg_packet_x as i32, 400, 35, 4, Color::new(0, 255, 200, 12));

        d.draw_text("AINCRAD-XDP", 515, 45, 42, Color::CYAN);
        d.draw_text("Don't worry, I've got you covered.", 485, 95, 18, Color::LIGHTGRAY);

        d.draw_rectangle(40, 40, 320, 60, Color::new(35, 35, 35, 180));
        d.draw_rectangle_lines(40, 40, 320, 60, Color::DARKGRAY);
        let stats_text = format!("BLOCKED (LAST HR): {}", history.count_last_hour());
        d.draw_text(&stats_text, 60, 60, 18, Color::LIME);

        let start_x = 140;
        let start_y = 200;
        let card_width = 220;
        let card_height = 90;
        let padding = 30;

        for (index, client) in banned_ips.iter().enumerate() {
            let col = index % 4;
            let row = index / 4;
            let x = start_x + (col * (card_width + padding)) as i32;
            let y = start_y + (row * (card_height + padding)) as i32;

            let pct = client.cooldown_percentage();

            d.draw_rectangle(x, y, card_width, card_height, Color::new(35, 35, 35, 220));
            
            d.draw_rectangle_lines(x, y, card_width, card_height, Color::new(220, 50, 50, 150));

            let ip_str = format!("{}", client.ip);
            d.draw_text(&ip_str, x + 20, y + 22, 20, Color::RAYWHITE);

            let bar_x = x + 20;
            let bar_y = y + 60;
            let max_bar_width = card_width - 40;
            let current_bar_width = (max_bar_width as f32 * pct) as i32;

            d.draw_rectangle(bar_x, bar_y, max_bar_width, 6, Color::new(60, 60, 60, 255));
            d.draw_rectangle(bar_x, bar_y, current_bar_width, 6, Color::new(0, 255, 180, 255));
        }

        d.draw_rectangle(440, 630, 400, 40, Color::new(35, 35, 35, 255));
        d.draw_rectangle_lines(440, 630, 400, 40, Color::new(80, 80, 80, 255));
        d.draw_text("Search Whitelist / Blacklist...", 460, 642, 16, Color::DARKGRAY);
    }
}
