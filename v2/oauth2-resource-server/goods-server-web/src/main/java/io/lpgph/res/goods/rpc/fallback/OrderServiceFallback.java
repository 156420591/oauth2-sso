package io.lpgph.res.goods.rpc.fallback;

import io.lpgph.res.goods.rpc.IOrderService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service("orderService")
public class OrderServiceFallback implements IOrderService {

  @Override
  public String showMsg() {
    log.error("调用 showMsg 异常");
    return null;
  }
}
