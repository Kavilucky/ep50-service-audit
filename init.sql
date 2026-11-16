-- Журнал описи комплектующих при вскрытии техники (пример, эпизод 50). Выполняется один раз при первом запуске PostgreSQL.
-- Все данные в примерах вымышленные. Фото, серийные номера и данные клиента могут быть персональными данными: условия по 152-ФЗ проверьте у юриста.
-- Журнал защищён от случайных правок (запрет UPDATE и DELETE) и ведёт цепочку хешей записей. Это защита от ошибок и небрежности, а не от администратора базы с полным доступом.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS repair_orders (          -- заказ-наряд
  id         BIGSERIAL PRIMARY KEY,
  order_no   TEXT NOT NULL UNIQUE,                  -- номер заказ-наряда из подписи к фото
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hardware_audit_log (     -- журнал описи: одна запись = одно фото
  id                 BIGSERIAL PRIMARY KEY,
  order_id           BIGINT NOT NULL REFERENCES repair_orders(id),
  image_sha256       TEXT NOT NULL CHECK (image_sha256 ~ '^[0-9a-f]{64}$'),   -- SHA-256 исходного файла фото
  timestamp_utc      TIMESTAMPTZ NOT NULL,          -- точное время записи (задаётся триггером, UTC)
  photo_enc          BYTEA NOT NULL,                -- фото, зашифрованное AES-256-GCM
  enc_iv             BYTEA NOT NULL,
  enc_tag            BYTEA NOT NULL,
  serials            JSONB NOT NULL DEFAULT '[]',   -- распознанные серийные номера: [{component, serial, confidence}]
  needs_review       BOOLEAN NOT NULL DEFAULT false, -- низкая уверенность распознавания: проверить глазами
  engineer_chat      BIGINT,
  prev_record_sha256 TEXT NOT NULL,                 -- хеш предыдущей записи (пусто у первой)
  record_sha256      TEXT NOT NULL UNIQUE,          -- хеш этой записи: цепочка записей
  UNIQUE (order_id, image_sha256)                   -- то же фото второй раз не пишется
);
CREATE INDEX IF NOT EXISTS audit_order_idx ON hardware_audit_log (order_id);

-- Время и цепочка хешей ставятся в базе, а не в сценарии: клиент сценария не может подсунуть своё время.
CREATE OR REPLACE FUNCTION audit_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev TEXT;
BEGIN
  PERFORM pg_advisory_xact_lock(5050);
  NEW.timestamp_utc := clock_timestamp();
  SELECT record_sha256 INTO prev FROM hardware_audit_log ORDER BY id DESC LIMIT 1;
  NEW.prev_record_sha256 := COALESCE(prev, '');
  NEW.record_sha256 := encode(digest(NEW.prev_record_sha256 || '|' || NEW.order_id::text || '|' || NEW.image_sha256 || '|' ||
                       to_char(NEW.timestamp_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'sha256'), 'hex');
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS audit_before_insert_trg ON hardware_audit_log;
CREATE TRIGGER audit_before_insert_trg BEFORE INSERT ON hardware_audit_log FOR EACH ROW EXECUTE FUNCTION audit_before_insert();

CREATE OR REPLACE FUNCTION audit_no_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'журнал описи только для добавления: UPDATE и DELETE запрещены';
END $$;
DROP TRIGGER IF EXISTS audit_no_change_trg ON hardware_audit_log;
CREATE TRIGGER audit_no_change_trg BEFORE UPDATE OR DELETE ON hardware_audit_log FOR EACH ROW EXECUTE FUNCTION audit_no_change();

-- Проверка цепочки: число записей, у которых хеш не сходится с предыдущей записью или с собственными данными (0 = цепочка цела).
CREATE OR REPLACE FUNCTION verify_audit_chain() RETURNS BIGINT LANGUAGE sql STABLE AS $$
  SELECT count(*) FROM (
    SELECT prev_record_sha256, record_sha256, order_id, image_sha256, timestamp_utc,
           lag(record_sha256) OVER (ORDER BY id) AS lag_hash
    FROM hardware_audit_log
  ) t
  WHERE prev_record_sha256 IS DISTINCT FROM COALESCE(lag_hash, '')
     OR record_sha256 <> encode(digest(prev_record_sha256 || '|' || order_id::text || '|' || image_sha256 || '|' ||
                          to_char(timestamp_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'sha256'), 'hex')
$$;
