using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.StackExchangeRedis;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace Microsoft.Extensions.Hosting;

public static class RedisDataProtectionExtensions
{
    public static void AddSharedDataProtection(this IHostApplicationBuilder builder, string applicationName)
    {
        builder.AddRedisClient("redis");
        builder.Services.AddDataProtection().SetApplicationName(applicationName);
        builder.Services.AddOptions<Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions>().Configure<IConnectionMultiplexer>((options, redis) =>
            options.XmlRepository = new RedisXmlRepository(() => redis.GetDatabase(), applicationName + ":keys"));
    }
}
