// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/color-util.c

pub const SOURCE_PATH: &str = "src/shared/color-util.c";
pub const SOURCE_TEXT: &str = include_str!("../color-util.c");

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RgbColor {
    pub r: f64,
    pub g: f64,
    pub b: f64,
}

impl RgbColor {
    pub fn new(r: f64, g: f64, b: f64) -> Self {
        assert!((0.0..=1.0).contains(&r), "red must be in [0.0, 1.0]");
        assert!((0.0..=1.0).contains(&g), "green must be in [0.0, 1.0]");
        assert!((0.0..=1.0).contains(&b), "blue must be in [0.0, 1.0]");

        Self { r, g, b }
    }

    pub fn to_hsv(self) -> HsvColor {
        let max_color = self.r.max(self.g).max(self.b);
        let min_color = self.r.min(self.g).min(self.b);
        let delta = max_color - min_color;

        let v = max_color * 100.0;

        if max_color <= 0.0 {
            return HsvColor {
                h: f64::NAN,
                s: 0.0,
                v,
            };
        }

        let s = delta / max_color * 100.0;
        let h = if delta > 0.0 {
            let h = if self.r >= max_color {
                60.0 * ((self.g - self.b) / delta % 6.0)
            } else if self.g >= max_color {
                60.0 * (((self.b - self.r) / delta) + 2.0)
            } else {
                60.0 * (((self.r - self.g) / delta) + 4.0)
            };

            h % 360.0
        } else {
            f64::NAN
        };

        HsvColor { h, s, v }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HsvColor {
    pub h: f64,
    pub s: f64,
    pub v: f64,
}

impl HsvColor {
    pub fn new(h: f64, s: f64, v: f64) -> Self {
        assert!(
            (0.0..=100.0).contains(&s),
            "saturation must be in [0.0, 100.0]"
        );
        assert!((0.0..=100.0).contains(&v), "value must be in [0.0, 100.0]");

        Self { h, s, v }
    }

    pub fn to_rgb(self) -> (u8, u8, u8) {
        let h = self.h % 360.0;
        let c = (self.s / 100.0) * (self.v / 100.0);
        let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
        let m = (self.v / 100.0) - c;

        let (r, g, b) = if (0.0..60.0).contains(&h) {
            (c, x, 0.0)
        } else if (60.0..120.0).contains(&h) {
            (x, c, 0.0)
        } else if (120.0..180.0).contains(&h) {
            (0.0, c, x)
        } else if (180.0..240.0).contains(&h) {
            (0.0, x, c)
        } else if (240.0..300.0).contains(&h) {
            (x, 0.0, c)
        } else {
            (c, 0.0, x)
        };

        (
            ((r + m) * 255.0) as u8,
            ((g + m) * 255.0) as u8,
            ((b + m) * 255.0) as u8,
        )
    }
}

pub fn rgb_to_hsv(color: RgbColor) -> HsvColor {
    color.to_hsv()
}

pub fn hsv_to_rgb(color: HsvColor) -> (u8, u8, u8) {
    color.to_rgb()
}

pub fn source_lines() -> usize {
    SOURCE_TEXT.lines().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_close(actual: f64, expected: f64, tolerance: f64) {
        assert!(
            (actual - expected).abs() <= tolerance,
            "expected {expected}, got {actual}"
        );
    }

    #[test]
    fn source_is_embedded() {
        assert!(!SOURCE_TEXT.is_empty());
    }

    #[test]
    fn rgb_to_hsv_matches_c_black_case() {
        let hsv = RgbColor::new(0.0, 0.0, 0.0).to_hsv();

        assert!(hsv.h.is_nan());
        assert_eq!(hsv.s, 0.0);
        assert_eq!(hsv.v, 0.0);
    }

    #[test]
    fn rgb_to_hsv_matches_c_white_case() {
        let hsv = RgbColor::new(1.0, 1.0, 1.0).to_hsv();

        assert!(hsv.h.is_nan());
        assert_eq!(hsv.s, 0.0);
        assert_eq!(hsv.v, 100.0);
    }

    #[test]
    fn rgb_to_hsv_matches_c_primary_colors() {
        let red = RgbColor::new(1.0, 0.0, 0.0).to_hsv();
        assert!(red.h >= 359.0 || red.h <= 1.0);
        assert!(red.s >= 100.0);
        assert!(red.v >= 100.0);

        let green = RgbColor::new(0.0, 1.0, 0.0).to_hsv();
        assert!((119.0..=121.0).contains(&green.h));
        assert!(green.s >= 100.0);
        assert!(green.v >= 100.0);

        let blue = RgbColor::new(0.0, 0.0, 1.0).to_hsv();
        assert!((239.0..=241.0).contains(&blue.h));
        assert!(blue.s >= 100.0);
        assert!(blue.v >= 100.0);
    }

    #[test]
    fn rgb_to_hsv_matches_c_nontrivial_case() {
        let hsv = RgbColor::new(0.5, 0.6, 0.7).to_hsv();

        assert!((209.0..=211.0).contains(&hsv.h));
        assert!((28.0..=31.0).contains(&hsv.s));
        assert!((69.0..=71.0).contains(&hsv.v));
    }

    #[test]
    fn rgb_to_hsv_preserves_c_negative_hue_behavior() {
        let hsv = RgbColor::new(1.0, 0.0, 0.5).to_hsv();

        assert_close(hsv.h, -30.0, 1e-9);
        assert_close(hsv.s, 100.0, 1e-9);
        assert_close(hsv.v, 100.0, 1e-9);
    }

    #[test]
    fn hsv_to_rgb_matches_c_documented_cases() {
        assert_eq!(HsvColor::new(0.0, 0.0, 0.0).to_rgb(), (0, 0, 0));
        assert_eq!(HsvColor::new(60.0, 0.0, 0.0).to_rgb(), (0, 0, 0));
        assert_eq!(HsvColor::new(0.0, 0.0, 100.0).to_rgb(), (255, 255, 255));
        assert_eq!(HsvColor::new(0.0, 100.0, 100.0).to_rgb(), (255, 0, 0));
        assert_eq!(HsvColor::new(120.0, 100.0, 100.0).to_rgb(), (0, 255, 0));
        assert_eq!(HsvColor::new(240.0, 100.0, 100.0).to_rgb(), (0, 0, 255));
        assert_eq!(HsvColor::new(311.0, 52.0, 62.0).to_rgb(), (158, 75, 143));
    }

    #[test]
    fn hsv_to_rgb_matches_c_hue_wrapping() {
        assert_eq!(HsvColor::new(480.0, 100.0, 100.0).to_rgb(), (0, 255, 0));
    }

    #[test]
    fn hsv_to_rgb_matches_c_mid_gray_truncation() {
        assert_eq!(HsvColor::new(0.0, 0.0, 50.0).to_rgb(), (127, 127, 127));
    }

    #[test]
    fn free_functions_delegate_to_methods() {
        let rgb = RgbColor::new(0.5, 0.3, 0.7);
        let hsv = rgb_to_hsv(rgb);
        assert_eq!(hsv, rgb.to_hsv());

        let hsv = HsvColor::new(270.0, 50.0, 80.0);
        assert_eq!(hsv_to_rgb(hsv), hsv.to_rgb());
    }

    #[test]
    fn roundtrip_stays_close_after_u8_quantization() {
        let original = RgbColor::new(0.5, 0.3, 0.8);
        let hsv = original.to_hsv();
        let (r, g, b) = hsv.to_rgb();

        assert_close(r as f64 / 255.0, original.r, 1.0 / 255.0);
        assert_close(g as f64 / 255.0, original.g, 1.0 / 255.0);
        assert_close(b as f64 / 255.0, original.b, 1.0 / 255.0);
    }

    #[test]
    #[should_panic(expected = "red must be in [0.0, 1.0]")]
    fn rgb_color_new_rejects_out_of_range_channels() {
        let _ = RgbColor::new(1.1, 0.0, 0.0);
    }

    #[test]
    #[should_panic(expected = "saturation must be in [0.0, 100.0]")]
    fn hsv_color_new_rejects_out_of_range_saturation() {
        let _ = HsvColor::new(0.0, 101.0, 50.0);
    }

    #[test]
    #[should_panic(expected = "value must be in [0.0, 100.0]")]
    fn hsv_color_new_rejects_out_of_range_value() {
        let _ = HsvColor::new(0.0, 50.0, 101.0);
    }
}
