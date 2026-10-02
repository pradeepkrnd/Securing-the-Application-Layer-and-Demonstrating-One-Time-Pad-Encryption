import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/** Local educational API. Not a production web security framework. */
public class Layer7Protection {
    private static final int MAX_BODY = 1024;
    private static final Pattern PROFILE = Pattern.compile(
        "[ \\t\\r\\n]*\\{[ \\t\\r\\n]*\"username\"[ \\t\\r\\n]*:[ \\t\\r\\n]*"
        + "\"([A-Za-z0-9_.-]{3,32})\"[ \\t\\r\\n]*\\}[ \\t\\r\\n]*");
    private static final Pattern JSON_TYPE = Pattern.compile(
        "application/json(?:\\s*;\\s*charset\\s*=\\s*(?:utf-8|\"utf-8\"))?");
    private final byte[] expectedKey;
    private final RateLimit limiter = new RateLimit();

    private Layer7Protection(String key) {
        expectedKey = key.getBytes(StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws IOException {
        String key = System.getenv("APP_API_KEY");
        if (key == null || key.length() < 24) {
            System.err.println("APP_API_KEY must contain at least 24 characters.");
            System.exit(1);
        }
        int port = args.length == 0 ? 8080 : Integer.parseInt(args[0]);
        Layer7Protection app = new Layer7Protection(key);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 32);
        server.createContext("/api/profile", app::handle);
        server.setExecutor(new ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(32), new ThreadPoolExecutor.CallerRunsPolicy()));
        server.start();
        System.out.println("Listening on http://127.0.0.1:" + server.getAddress().getPort());
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'");
            exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
            exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
            int retry = limiter.retryAfter();
            if (retry > 0) {
                exchange.getResponseHeaders().set("Retry-After", Integer.toString(retry));
                send(exchange, 429, "{\"error\":\"Too many requests\"}");
                return;
            }
            if (!exchange.getRequestURI().getPath().equals("/api/profile")) {
                send(exchange, 404, "{\"error\":\"Not found\"}");
                return;
            }
            if (!exchange.getRequestMethod().equals("POST")) {
                exchange.getResponseHeaders().set("Allow", "POST");
                send(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }
            String supplied = exchange.getRequestHeaders().getFirst("X-API-Key");
            if (supplied == null || !MessageDigest.isEqual(expectedKey,
                    supplied.getBytes(StandardCharsets.UTF_8))) {
                exchange.getResponseHeaders().set("WWW-Authenticate", "ApiKey realm=\"profile\"");
                send(exchange, 401, "{\"error\":\"Unauthorized\"}");
                return;
            }
            String type = exchange.getRequestHeaders().getFirst("Content-Type");
            if (type == null || !JSON_TYPE.matcher(type.strip().toLowerCase(Locale.ROOT)).matches()) {
                send(exchange, 415, "{\"error\":\"Unsupported media type\"}");
                return;
            }
            byte[] bytes = exchange.getRequestBody().readNBytes(MAX_BODY + 1);
            if (bytes.length > MAX_BODY) {
                send(exchange, 413, "{\"error\":\"Request too large\"}");
                return;
            }
            String body;
            try {
                body = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            } catch (CharacterCodingException invalidEncoding) {
                send(exchange, 400, "{\"error\":\"Invalid request data\"}");
                return;
            }
            var match = PROFILE.matcher(body);
            if (!match.matches()) {
                send(exchange, 400, "{\"error\":\"Invalid request data\"}");
                return;
            }
            send(exchange, 200, "{\"status\":\"accepted\",\"username\":\"" + match.group(1) + "\"}");
        }
    }

    private static void send(HttpExchange exchange, int code, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(code, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    /** Global five-request quota for this single-client loopback demonstration. */
    private static final class RateLimit {
        private long start = System.nanoTime();
        private int count;
        synchronized int retryAfter() {
            long elapsed = System.nanoTime() - start;
            if (elapsed >= TimeUnit.SECONDS.toNanos(60)) {
                start = System.nanoTime();
                count = 0;
                elapsed = 0;
            }
            if (count >= 5) {
                return (int) Math.max(1, (TimeUnit.SECONDS.toNanos(60) - elapsed
                    + TimeUnit.SECONDS.toNanos(1) - 1) / TimeUnit.SECONDS.toNanos(1));
            }
            count++;
            return 0;
        }
    }
}
