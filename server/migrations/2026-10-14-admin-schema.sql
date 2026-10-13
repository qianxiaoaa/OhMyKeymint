-- =========================================================
-- OMK 管理后台 schema 参考（2026-10-14）
--
-- 实际运行用的是 SQLite（server/data/admin.sqlite），由 qianxiao/lib/db.php 的
-- admin_db() 首跑「自愈建表」，无需手工执行本文件。
-- 这份 MySQL 版仅作【迁库参考】：若要后台改用 MySQL，按此建表即可与代码等价。
-- 注意 qianxiao/lib/db.php 里的 SQLite DDL 才是权威定义，改表时两边同步。
--
-- 用法：  mysql -u <user> -p <db> < 2026-10-14-admin-schema.sql
-- =========================================================

-- 管理员账号：口令只存 bcrypt，磁盘无明文。enabled=0 视为停用。
CREATE TABLE IF NOT EXISTS admin_user (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  user          VARCHAR(32)  NOT NULL,
  pass_hash     VARCHAR(255) NOT NULL,
  enabled       TINYINT      NOT NULL DEFAULT 1,
  last_login_at DATETIME     NULL,
  created_at    DATETIME     NOT NULL,
  UNIQUE KEY uk_user (user)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 领取/分发埋点：public/index.php 的 keybox / manifest 分支匿名写入。
-- at 为 UTC 文本；分发无设备标识，只有 IP/UA/keybox sha/序列号串。
CREATE TABLE IF NOT EXISTS usage_log (
  id             BIGINT AUTO_INCREMENT PRIMARY KEY,
  at             VARCHAR(19) NOT NULL,
  ip             VARCHAR(45) NOT NULL,
  ua             VARCHAR(200) DEFAULT NULL,
  action         VARCHAR(16) NOT NULL,
  keybox_sha256  CHAR(64)    DEFAULT NULL,
  keybox_serials TEXT        DEFAULT NULL,
  note           TEXT        DEFAULT NULL,
  INDEX idx_usage_at (at),
  INDEX idx_usage_ip (ip),
  INDEX idx_usage_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 设备台账：file_path 由服务端按 sha256(imei) 生成文件名，与 data/devices/<hash>.json 双写。
-- file_path 只存【相对文件名】（不含目录），运行时由 admin_devices_dir() 拼接；存绝对路径
-- 会在后台换目录部署后当场失效（无存量库，直接以该语义建表）。
CREATE TABLE IF NOT EXISTS device (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  imei        VARCHAR(16)  NOT NULL,
  fingerprint VARCHAR(300) NOT NULL,
  note        VARCHAR(200) DEFAULT NULL,
  enabled     TINYINT      NOT NULL DEFAULT 1,
  created_at  VARCHAR(19)  NOT NULL,
  file_path   VARCHAR(255) NOT NULL COMMENT '台账档案相对文件名（如 <hash>.json），不存目录',
  UNIQUE KEY uk_device_imei (imei)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 后台操作审计：登录成败 + 设备/账号增删改（谁、什么时候、对哪个对象、从哪个 IP）。
CREATE TABLE IF NOT EXISTS audit (
  id     BIGINT AUTO_INCREMENT PRIMARY KEY,
  admin  VARCHAR(32) NOT NULL,
  act    VARCHAR(24) NOT NULL,
  target VARCHAR(255) DEFAULT NULL,
  ip     VARCHAR(45)  DEFAULT NULL,
  at     VARCHAR(19) NOT NULL,
  INDEX idx_audit_at (at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 登录失败限流小表（等价 dashboard 的 ac_login_fail）：一行一次失败。
CREATE TABLE IF NOT EXISTS login_fail (
  ip  VARCHAR(45) NOT NULL,
  at  VARCHAR(19) NOT NULL,
  cnt TINYINT     NOT NULL DEFAULT 1,
  INDEX idx_login_fail_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
