package spring.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import spring.security.user.User;
import spring.security.user.UserService;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor // 생성자주입
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserService userService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //basic authentication filter disable
        http.httpBasic().disable();
        //csrf
        http.csrf();
        //rememberMe
        http.rememberMe();

        //authorization
        http.authorizeRequests()
                // /, /home, /signup
                .antMatchers("/", "/home", "/signup").permitAll()
                .antMatchers("/note").hasRole("USER") //유저 권환만
                .antMatchers("/admin").hasRole("ADMIN") //어드민 권한만
                //.antMatchers(HttpMethod.GET, "/notice").authenticated()      anyRequest()에서 처리되기떄문에 없어도 상관없음
                .antMatchers(HttpMethod.POST, "/notice").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/notice").hasRole("ADMIN")
                .anyRequest().authenticated();

        //login
        http.formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/") //로그인 성공시 이동할 url
                .permitAll();

        //logout
        http.logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // 로그아웃 요청 경로
                .logoutSuccessUrl("/"); //로그아웃 성공시 이동할 url


    }

    @Override
    public void configure(WebSecurity web) throws Exception{
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        return username -> {
            User user = userService.findByUsername(username);
            if(user == null){
                throw new UsernameNotFoundException(username);
            }
            return user;
        };
    }
}