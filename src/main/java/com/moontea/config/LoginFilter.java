package com.moontea.config;

public class LoginFilter extends AbstractAuthenticationProcessingFilter{
	
	public JWTLoginFilter(String url, AuthenticationManager authManager) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authManager);
    }
    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException, IOException, ServletException {

    	String username = req.getParameter("username");
        String password = req.getParameter("password");

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();
        // 觸發AuthenticationManager
        return getAuthenticationManager().authenticate(
                new UsernamePasswordAuthenticationToken(
                		username,password
                )
        );
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest req,
            HttpServletResponse res, FilterChain chain,
            Authentication auth) throws IOException, ServletException {
    	// 登入成功，將token透過JwtUtil放到res中
        JwtUtil.addAuthentication(res, auth);
    }


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().println(JSONResult.fillResultString(401, "Loing error!!!", JSONObject.NULL));
    }
}