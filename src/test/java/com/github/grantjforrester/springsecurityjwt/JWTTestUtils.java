package com.github.grantjforrester.springsecurityjwt;

class JWTTestUtils {

    /*
     * This JWT has claims {"sub":"John Smith","jti":"1234-5678","roles":["someRole"]}
     * and is signed with the key 'dev-hmac' from 'testkeyset.jwks.
     */
    static final String JWT_WITH_HMAC_SIG = "eyJraWQiOiJkZXYtaG1hYyIsImFsZyI6IkhTMjU2In0"
            + ".eyJzdWIiOiJKb2huIFNtaXRoIiwicm9sZXMiOlsic29tZVJvbGUiXSwianRpIjoiMTIzNC01Njc4In0"
            + ".TctNQvjY9ty-QHc0e59pD0ww-ntB4YB5feHWthXuQEU";

    /*
     * This JWT has claims {"sub":"John Smith","jti":"1234-5678","roles":["someRole"]}
     * and is signed with the key 'dev-rsa' from 'testkeyset.jwks.
     */
    static final String JWT_WITH_RSA_SIG = "eyJraWQiOiJkZXYtcnNhIiwiYWxnIjoiUlMyNTYifQ"
            + ".eyJzdWIiOiJKb2huIFNtaXRoIiwicm9sZXMiOlsic29tZVJvbGUiXSwianRpIjoiMTIzNC01Njc4In0"
            + ".YdYHkPgSuPbsGJ6F_bu9MyWcLmzAROw-H0RpB8dJFSAOCgMtNcGtDxUm8Y6Zw8RrbJmD1fc9HAhKWUS"
            + "Z6wwuvMXHVqnkAI4bdnDL_wpQglzHFjL2Wv3E8rC589I6XgZF2Ha59zclsSfR_PgHWXdKKpsHpwKNPxM"
            + "8uWAvFALAgKDFPku4nyddUVy4YU-Svt-TK73EyLve9yCtj1oOATJI0BciIlOdttN3jtg5w3FXqIwibYT"
            + "0TvTF7AFB6AEEbgyQ4rVy_mvQJGU72HZLQtFvwrZzO1s1qPy3dIo9-NV-eb_fzMKEzAHKD-j0LlueOCv"
            + "bhyWVbflQ4CC3gyWB5FgSfQ";

    /*
     * This JWT has claims {"sub":"John Smith","jti":"1234-5678","roles":["someRole"]}
     * and is signed with the key 'dev-ec' from 'testkeyset.jwks.
     */
    static final String JWT_WITH_EC_SIG = "eyJraWQiOiJkZXYtZWMiLCJhbGciOiJFUzI1NiJ9"
            + ".eyJzdWIiOiJKb2huIFNtaXRoIiwicm9sZXMiOlsic29tZVJvbGUiXSwianRpIjoiMTIzNC01Njc4In0"
            + ".75XRiXVn4zOFNVa3KwktgG4vk2y9Rw0xK2QdZOoU7lf9ajWWT36_Nm5BI1rH8y2eEMWlkYUnwUddwzl"
            + "WKA2hQg";

    static final String MALFORMED_JWT = "fkrhfkrfhr8frf";

    static final String JWT_WITH_NO_KID = "eyJhbGciOiJIUzI1NiJ9"
            + ".eyJzdWIiOiJKb2huIFNtaXRoIiwianRpIjoiMTIzNC01Njc4In0"
            + ".tTqfjnzH8iNEwVAvEJ0aIaR75YW0Z6bz8lblG9GQVDQ";

    static final String JWT_WITH_UNKNOWN_KID = "eyJraWQiOiJtaXNzaW5nIiwiYWxnIjoiSFMyNTYifQ"
            + ".eyJzdWIiOiJKb2huIFNtaXRoIiwianRpIjoiMTIzNC01Njc4In0"
            + ".rzxnYOMEArtaOc1BhgBOip9dpNlwsZcjpPxjj_NciG0";

    static final String JWT_WITH_INVALID_SIG = "eyJraWQiOiJkZXYtaG1hYyIsImFsZyI6IkhTMjU2In0"
            + ".eyJzdWIiOiJKb2huIFNtaXRoIiwianRpIjoiMTIzNC01Njc4In0"
            + "._0yaWQ9YZiR3ktuC4DIJKASokaOdpFfBSobbL3Y-HZs";

    public static final String EXPIRED_JWT = "eyJraWQiOiJkZXYtaG1hYyIsImFsZyI6IkhTMjU2In0"
            + ".eyJzdWIiOiJKb2huIFNtaXRoIiwianRpIjoiMTIzNC01Njc4IiwiZXhwIjoxNTQ1MTMzNjQ4fQ"
            + ".9-PyQGAiVeDbK6HL41huBZfScA-rXgLePQ_X5uDGg2Q";
}
