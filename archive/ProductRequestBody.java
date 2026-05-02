package com.droisys.mintid.ResponseBody;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Faithful reconstruction of ProductRequestBody from MintID 1.8 (APKPure).
 *
 * Source of truth: classes.dex, Lcom/droisys/mintid/ResponseBody/ProductRequestBody;
 *
 * Field declaration order in DEX (also the order Jackson serializes in,
 * since there is no @JsonPropertyOrder on the class):
 *   1. DeviceID, 2. DeviceType, 3. Lat, 4. Lon,
 *   5. TagCrypto, 6. TagProvider, 7. TagType, 8. TagUID, 9. TagValue
 *
 * Constructor parameter order (different from field declaration order):
 *   p1=DeviceType, p2=DeviceID, p3=Lat, p5=Lon,
 *   p7=TagProvider, p8=TagType, p9=TagValue, p10=TagUID, p11=TagCrypto
 *
 * Each field has a @JsonProperty annotation (verified by direct parsing
 * of the DEX annotations directory). The annotation's value element is
 * the field name verbatim, so the JSON key matches the Java field name.
 *
 * The @JsonProperty annotations are essential: they let Jackson's default
 * ObjectMapper (used by Retrofit's JacksonConverterFactory.create()) find
 * these private final fields without needing fieldVisibility=ANY. This is
 * the critical piece that makes the real app's serialization work end to end.
 */
public class ProductRequestBody {
    @JsonProperty("DeviceID")
    private final String DeviceID;

    @JsonProperty("DeviceType")
    private final String DeviceType;

    @JsonProperty("Lat")
    private final double Lat;

    @JsonProperty("Lon")
    private final double Lon;

    @JsonProperty("TagCrypto")
    private final String TagCrypto;

    @JsonProperty("TagProvider")
    private final String TagProvider;

    @JsonProperty("TagType")
    private final String TagType;

    @JsonProperty("TagUID")
    private final String TagUID;

    @JsonProperty("TagValue")
    private final String TagValue;

    public ProductRequestBody(
        String p1,
        String p2,
        double p3,
        double p5,
        String p7,
        String p8,
        String p9,
        String p10,
        String p11
    ) {
        this.DeviceType = p1;
        this.DeviceID = p2;
        this.Lat = p3;
        this.Lon = p5;
        this.TagProvider = p7;
        this.TagType = p8;
        this.TagUID = p10;
        this.TagValue = p9;
        this.TagCrypto = p11;
    }
}
