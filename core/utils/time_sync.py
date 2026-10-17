import time
import httpx
from datetime import datetime, timezone, timedelta
from loguru import logger

def get_real_time_sync() -> datetime:
    """
    尝试从可靠的公共 API 获取真实世界的时间 (北京时间 UTC+8)。
    如果所有 API 都失败或超时，则回退到本地系统时间 + 强制 UTC+8 偏移。
    """
    beijing_tz = timezone(timedelta(hours=8))
    
    # 备选的时间 API 列表
    time_apis = [
        "http://api.m.taobao.com/rest/api3.do?api=mtop.common.getTimestamp",  # 淘宝时间戳 API (毫秒)
        "https://worldtimeapi.org/api/timezone/Asia/Shanghai",               # WorldTimeAPI
        "http://quan.suning.com/getSysTime.do"                               # 苏宁易购时间 API
    ]
    
    with httpx.Client(timeout=3.0, verify=False) as client:
        for api_url in time_apis:
            try:
                resp = client.get(api_url)
                if resp.status_code == 200:
                    data = resp.json()
                    
                    if "taobao" in api_url:
                        ts_ms = int(data["data"]["t"])
                        real_time = datetime.fromtimestamp(ts_ms / 1000.0, tz=beijing_tz)
                        return real_time
                        
                    elif "worldtimeapi" in api_url:
                        datetime_str = data.get("datetime")
                        if datetime_str:
                            real_time = datetime.fromisoformat(datetime_str)
                            return real_time
                            
                    elif "suning" in api_url:
                        sys_time2 = data.get("sysTime2") # 格式: "2023-10-25 14:30:00"
                        if sys_time2:
                            real_time = datetime.strptime(sys_time2, "%Y-%m-%d %H:%M:%S").replace(tzinfo=beijing_tz)
                            return real_time
                            
            except Exception as e:
                logger.debug(f"从 {api_url} 获取时间失败: {e}")
                continue
                
    # 如果所有 API 都失败，强制使用本地机器时间并转换为 UTC+8
    logger.warning("所有外部时间 API 获取失败，回退到本地系统时间计算的 UTC+8。")
    return datetime.now(timezone.utc).astimezone(beijing_tz)

def get_formatted_real_time() -> str:
    """获取格式化后的真实时间字符串，例如 '2026-04-02 10:09:53'"""
    return get_real_time_sync().strftime("%Y-%m-%d %H:%M:%S")
