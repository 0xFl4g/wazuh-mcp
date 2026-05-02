-- Atomic token-bucket refill + consume.
-- KEYS[1] = bucket key (Redis hash)
-- ARGV[1] = capacity (integer, max tokens)
-- ARGV[2] = refill_per_sec (float)
-- ARGV[3] = now_ms (integer, server-supplied wall clock in ms)
-- ARGV[4] = n_tokens (integer, tokens to consume; usually 1)
-- ARGV[5] = ttl_sec (integer, key expiry to apply on every write)
--
-- Returns: 1 if granted, 0 if denied.
-- Side effect: hash fields {tokens, last_refill_ms} updated, key TTL refreshed.

local capacity = tonumber(ARGV[1])
local refill   = tonumber(ARGV[2])
local now_ms   = tonumber(ARGV[3])
local n        = tonumber(ARGV[4])
local ttl      = tonumber(ARGV[5])

local h = redis.call('HMGET', KEYS[1], 'tokens', 'last_refill_ms')
local tokens = tonumber(h[1])
local last   = tonumber(h[2])

if tokens == nil then
  -- New bucket: start full.
  tokens = capacity
  last   = now_ms
end

local elapsed_sec = (now_ms - last) / 1000.0
if elapsed_sec < 0 then
  -- Clock skew on caller side. Don't credit negative time; just refresh last_refill_ms.
  elapsed_sec = 0
end

tokens = math.min(capacity, tokens + elapsed_sec * refill)

if tokens < n then
  -- Denied. Persist the refill but not the consume, so retries see updated state.
  redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_refill_ms', now_ms)
  redis.call('EXPIRE', KEYS[1], ttl)
  return 0
end

tokens = tokens - n
redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_refill_ms', now_ms)
redis.call('EXPIRE', KEYS[1], ttl)
return 1
