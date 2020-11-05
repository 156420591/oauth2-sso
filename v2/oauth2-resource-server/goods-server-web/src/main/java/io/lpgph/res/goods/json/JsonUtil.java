package io.lpgph.res.goods.json;

import lombok.extern.slf4j.Slf4j;

import java.io.Writer;
import java.util.Objects;

/**
 * Json工具类 <br>
 * Create Date: 3/31/18 4:10 PM <br>
 *
 * @author Peter Guo
 * @version 0.1
 */
@Slf4j
public class JsonUtil {

  /** 声明ObjectMapper */
  public static final DefaultObjectMapper objectMapper = new DefaultObjectMapper();

  /**
   * 将对象转换成json字符串,支持单个对象，数组，字符串等
   *
   * @param o 对象
   * @return json字符串
   */
  public static String toJson(Object o) {
    return objectMapper.writeValueAsString(o);
  }

  public static void toJson(Writer writer, Object o) {
    objectMapper.writeValue(writer, o);
  }

  /**
   * 指定单个对象转换
   *
   * @param jsonStr 需要转换的的json字符串的对象
   * @param valueType Class 类型
   * @param <T> 转换类型
   * @return 返回单个对象
   */
  public static <T> T fromJson(String jsonStr, Class<T> valueType) {
    if (isBlank(jsonStr)) {
      return null;
    }
    return objectMapper.readValue(jsonStr, valueType);
  }

  /**
   * 指定类型转换，如果数组，集合
   *
   * @param jsonStr 需要转换的的json字符串
   * @param typeReference new TypeReference<List<RoleModuleEntity>>(){});
   * @param <T> 转换类型，如 List<RoleModuleEntity>, String[]
   * @return 返回集合，数组等
   */
  public static <T> T fromJson(String jsonStr, TypeReference<T> typeReference) {
    if (isBlank(jsonStr)) {
      return null;
    }
    return objectMapper.readValue(jsonStr, typeReference);
  }

  private static boolean isBlank(String str) {
    return str == null || str.trim().isEmpty() || Objects.hashCode(str) == 0;
  }
}
