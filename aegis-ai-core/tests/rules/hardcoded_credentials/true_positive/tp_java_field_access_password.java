class ConfigWriter {
    void configure(AppConfig config) {
        config.password = "prodPassword12345";
    }
}

class AppConfig {
    String password;
}
