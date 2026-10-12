-- =========================================================
-- yypm 反挂服务端 v2.7.0 迁移：设备令牌 + 限流 + 操作审计
-- 在 yypm 库上执行：  mysql -u yypm -p yypm < 2026-10-02-acreport-v2.sql
-- （代码里也带了「表不存在就自愈建表」的兜底，跑不跑这份 SQL 都能活，
--   但建议跑 —— 自愈失败时接口会退化成只读。）
-- =========================================================

-- 设备令牌：首次联系下发一次，之后 expire（封禁）必须带牌。
-- 存的是 sha256(token)，库里不落令牌原文。
CREATE TABLE IF NOT EXISTS ac_token (
  code       CHAR(16)  PRIMARY KEY,
  tok_hash   CHAR(64)  NOT NULL,
  created_at DATETIME  NOT NULL,
  last_seen  DATETIME  NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 限流桶：k = "ip:<ip>" / "code:<设备码>" / "exp:<设备码>"
CREATE TABLE IF NOT EXISTS ac_ratelimit (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  k   VARCHAR(64) NOT NULL,
  at  DATETIME    NOT NULL,
  INDEX idx_k (k),
  INDEX idx_at (at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 面板操作审计：登录成败 + 手动封禁/解封
CREATE TABLE IF NOT EXISTS ac_audit (
  id    BIGINT AUTO_INCREMENT PRIMARY KEY,
  admin VARCHAR(32) NOT NULL,
  act   VARCHAR(16) NOT NULL,
  code  CHAR(16)    DEFAULT NULL,
  ip    VARCHAR(45) DEFAULT NULL,
  at    DATETIME    NOT NULL,
  INDEX idx_at (at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
