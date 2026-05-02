package harness;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.droisys.mintid.ResponseBody.ProductRequestBody;
import java.io.PrintStream;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bytecode-faithful Java harness that produces the exact HTTP request the
 * MintID app emits when getProductInfo() calls
 * webApis.getProductDetailWithCrypto(productRequestBody).
 *
 * The harness:
 *  1. Constructs a ProductRequestBody using the same constants and call-site
 *     argument order as HelperTagReader.getProductInfo (and getProductInfoGenuin
 *     -- byte-identical at the call site).
 *  2. Serializes it via the SAME ObjectMapper that Retrofit's
 *     JacksonConverterFactory.create() uses (default no-arg).
 *  3. Builds the same request headers HelperTagReader$4.intercept adds.
 *  4. Writes the full request to /tmp/java_emitted_request.json so a Python
 *     comparison can diff it byte-for-byte against the simulator's output.
 *
 * Build (assumes Jackson 2.14 from libjackson2-databind-java):
 *   javac -d build \
 *     -cp /usr/share/java/jackson-core.jar:/usr/share/java/jackson-annotations.jar:/usr/share/java/jackson-databind.jar \
 *     src/com/droisys/mintid/ResponseBody/ProductRequestBody.java \
 *     src/harness/Harness.java
 *
 * Run:
 *   java -cp build:/usr/share/java/jackson-core.jar:/usr/share/java/jackson-annotations.jar:/usr/share/java/jackson-databind.jar \
 *        harness.Harness <tag_uid_lowercase_hex> <tag_crypto>
 *
 * Defaults (no args): uses the values from the user's most recent scan.
 */
public class Harness {

    public static void main(String[] args) throws Exception {
        String tagUid    = (args.length >= 1) ? args[0] : "ADF61606013C16E0";
        String tagCrypto = (args.length >= 2) ? args[1] : "A125B451690E7E8C4C33AF273DB1ACFB";

        // Step 1: build the body. Same constants and same call-site order as
        // HelperTagReader.getProductInfo invokes ProductRequestBody.<init>.
        //
        //   const-string v4,  "Android"           (DeviceType, p1)
        //   utilPrefrences.getKeyDeviceId()       (DeviceID, p2)            "" on fresh install
        //   gpsTracker.getLatitude()              (Lat, p3+p4)              0.0 if no permission
        //   gpsTracker.getLongitude()             (Lon, p5+p6)              0.0 if no permission
        //   const-string v10, "Identiv"           (TagProvider, p7)
        //   const-string v11, "NFC Tags"          (TagType, p8)
        //   const-string v12, "1234567812345678"  (TagValue, p9)
        //   v13 = tid (third arg of getProductInfo) (TagUID, p10)
        //   v14 = msgPayload (first arg)            (TagCrypto, p11)
        //
        ProductRequestBody body = new ProductRequestBody(
            "Android",            // p1  DeviceType
            "",                   // p2  DeviceID
            0.0,                  // p3  Lat
            0.0,                  // p5  Lon
            "Identiv",            // p7  TagProvider
            "NFC Tags",           // p8  TagType
            "1234567812345678",   // p9  TagValue
            tagUid,               // p10 TagUID
            tagCrypto             // p11 TagCrypto
        );

        // Step 2: serialize with default ObjectMapper (Retrofit's default).
        ObjectMapper mapper = new ObjectMapper();
        String jsonBody = mapper.writeValueAsString(body);

        // Step 3: build the request headers (HelperTagReader$4.intercept,
        // guest path -- token is empty; no SessionToken header).
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("OrgAccessID",      "000000000000000000000000");
        headers.put("AuthorizationKey", "2I0mGELp");
        headers.put("Content-Type",     "application/json");

        // Endpoint: Constants.BaseUrl + "ProductAuthentication/SecuredScanProduct"
        // Constants.BaseUrl = "http://mintidapi.droisys.info/api/"
        // WebApis.getProductDetailWithCrypto path = "ProductAuthentication/SecuredScanProduct"
        String url = "http://mintidapi.droisys.info/api/ProductAuthentication/SecuredScanProduct";

        // Display the assembled request.
        System.out.println("=== Field declaration order ===");
        Field[] fields = ProductRequestBody.class.getDeclaredFields();
        for (int i = 0; i < fields.length; i++) {
            System.out.println("  " + (i + 1) + ". " + fields[i].getName());
        }

        System.out.println();
        System.out.println("=== Assembled HTTP request ===");
        System.out.println("POST " + url);
        for (Map.Entry<String, String> e : headers.entrySet()) {
            System.out.println("  " + e.getKey() + ": " + e.getValue());
        }
        System.out.println("  Content-Length: " + jsonBody.getBytes("UTF-8").length);
        System.out.println();
        System.out.println(jsonBody);

        // Step 4: write a machine-readable representation for Python diff.
        // We emit a JSON envelope: {"url": ..., "headers": {...}, "body": "<raw bytes>",
        // "body_length": ..., "field_order": [...]}.
        Map<String, Object> envelope = new LinkedHashMap<String, Object>();
        envelope.put("url", url);
        envelope.put("headers", headers);
        envelope.put("body", jsonBody);
        envelope.put("body_length", jsonBody.getBytes("UTF-8").length);
        java.util.List<String> fieldOrder = new java.util.ArrayList<String>();
        for (Field f : fields) fieldOrder.add(f.getName());
        envelope.put("field_order", fieldOrder);

        ObjectMapper envelopeMapper = new ObjectMapper();
        envelopeMapper.enable(com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT);
        String envelopeJson = envelopeMapper.writeValueAsString(envelope);

        String outputPath = "/tmp/java_emitted_request.json";
        PrintStream fileOut = new PrintStream(new FileOutputStream(outputPath));
        fileOut.print(envelopeJson);
        fileOut.close();

        System.out.println();
        System.out.println("=== Wrote " + outputPath + " ===");
    }
}
