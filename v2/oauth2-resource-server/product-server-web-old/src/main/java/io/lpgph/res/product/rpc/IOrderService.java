package io.lpgph.res.product.rpc;

import io.lpgph.res.product.config.FeignClientConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(
    value = "order",
    configuration = FeignClientConfig.class)
public interface IOrderService {

  @GetMapping("/hello")
  String showMsg();

}
