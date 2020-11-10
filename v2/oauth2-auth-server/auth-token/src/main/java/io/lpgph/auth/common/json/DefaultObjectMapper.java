package io.lpgph.auth.common.json;

import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.deser.std.StdScalarDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdScalarSerializer;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.Writer;
import java.time.Instant;

import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import static com.fasterxml.jackson.core.JsonParser.Feature;
import static java.time.ZoneId.of;
import static java.util.TimeZone.getTimeZone;

@Slf4j
public final class DefaultObjectMapper extends ObjectMapper {

    public DefaultObjectMapper() {
        super();
        findAndRegisterModules()
                .setTimeZone(getTimeZone(of("Asia/Shanghai")))
                .setVisibility(PropertyAccessor.ALL, Visibility.NONE)
                .setVisibility(PropertyAccessor.FIELD, Visibility.ANY)
                .registerModule(instantModule())
                .registerModule(trimStringModule())
                .registerModule(new ParameterNamesModule())
                .registerModule(new Jdk8Module())
                .registerModule(new JavaTimeModule())
                .configure(Feature.ALLOW_UNQUOTED_FIELD_NAMES, true) // 允许键值不为双引号
                .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        //        registerModule(new DomainEventJacksonModule());
    }

    private SimpleModule instantModule() {
        return new JavaTimeModule()
                .addSerializer(Instant.class, instantSerializer())
                .addDeserializer(Instant.class, instantDeserializer());
    }

    private SimpleModule trimStringModule() {
        return new SimpleModule()
                .addDeserializer(
                        String.class,
                        new StdScalarDeserializer<>(String.class) {
                            @Override
                            public String deserialize(JsonParser jsonParser, DeserializationContext ctx)
                                    throws IOException {
                                return jsonParser.getValueAsString().trim();
                            }
                        })
                .addSerializer(
                        String.class,
                        new StdScalarSerializer<>(String.class) {
                            @Override
                            public void serialize(String value, JsonGenerator gen, SerializerProvider provider)
                                    throws IOException {
                                gen.writeString(value.trim());
                            }
                        });
    }

    private JsonDeserializer<Instant> instantDeserializer() {
        return new JsonDeserializer<Instant>() {
            @Override
            public Instant deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                return Instant.ofEpochMilli(p.getValueAsLong());
            }
        };
    }

    private JsonSerializer<Instant> instantSerializer() {
        return new JsonSerializer<Instant>() {
            @Override
            public void serialize(Instant value, JsonGenerator gen, SerializerProvider serializers)
                    throws IOException {
                gen.writeNumber(value.toEpochMilli());
            }
        };
    }

    @Override
    public String writeValueAsString(Object value) {
        try {
            return super.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            log.error(e.toString());
        }
        return null;
    }

    @Override
    public void writeValue(Writer w, Object value) {
        try {
            super.writeValue(_jsonFactory.createGenerator(w), value);
        } catch (Exception e) {
            log.error(e.toString());
        }
    }

    @Override
    public <T> T readValue(String content, Class<T> valueType) {
        try {
            return super.readValue(content, valueType);
        } catch (Exception e) {
            log.error(e.toString());
        }
        return null;
    }

    @Override
    public <T> T readValue(String content, TypeReference<T> valueTypeRef) {
        try {
            return super.readValue(content, valueTypeRef);
        } catch (Exception e) {
            log.error(e.toString());
        }
        return null;
    }
}
