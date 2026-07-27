class FetchController {
    void fetch(HttpServletRequest request) {
        String url = request.getParameter("url");
        new RestTemplate().getForObject(url, String.class);
    }
}
