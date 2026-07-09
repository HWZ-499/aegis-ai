class HealthClient {
    void check() {
        new RestTemplate().getForObject("https://api.example.com/health", String.class);
    }
}
