package io.lpgph.res.goods.rpc;

import io.lpgph.res.goods.config.FeignClientConfig;
import io.lpgph.res.goods.rpc.fallback.OrderServiceFallback;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(
    value = "order",
    fallback = OrderServiceFallback.class,
    configuration = FeignClientConfig.class)
public interface IOrderService {

  @GetMapping("/hello")
  String showMsg();

}
