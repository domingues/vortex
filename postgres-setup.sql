CREATE TABLE IF NOT EXISTS messages
(
    id          SERIAL PRIMARY KEY,
    "timestamp" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    content     BYTEA                    NOT NULL
);

CREATE OR REPLACE FUNCTION read_messages(
    since_id INT
)
    RETURNS TABLE
            (
                id          integer,
                "timestamp" TIMESTAMP WITH TIME ZONE,
                content     BYTEA
            )
AS
$$
BEGIN
    RETURN QUERY
        SELECT m.id AS message_id,
               m."timestamp",
               m.content
        FROM messages AS m
        WHERE m.id > since_id;
END;
$$ LANGUAGE plpgsql
    SECURITY DEFINER;

CREATE OR REPLACE FUNCTION send_messages(
    messages_to_insert BYTEA[]
) RETURNS VOID AS
$$
DECLARE
    message_bytea BYTEA;
BEGIN
    IF array_length(messages_to_insert, 1) > 0 THEN
        FOREACH message_bytea IN ARRAY messages_to_insert
            LOOP
                IF LENGTH(message_bytea) > 1024 THEN
                    RAISE EXCEPTION '';
                ELSE
                    INSERT INTO messages (content)
                    VALUES (message_bytea);
                END IF;
            END LOOP;
        NOTIFY new_messages;
    END IF;
END;
$$ LANGUAGE plpgsql
    SECURITY DEFINER;

CREATE OR REPLACE FUNCTION activate_listener()
    RETURNS VOID AS
$$
BEGIN
    LISTEN new_messages;
END;
$$ LANGUAGE plpgsql
    SECURITY DEFINER;

-- guest group and permissions
CREATE ROLE guest_group;

GRANT CONNECT ON DATABASE chat TO guest_group;

REVOKE ALL PRIVILEGES ON SCHEMA public FROM guest_group;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM guest_group;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM guest_group;
REVOKE ALL PRIVILEGES ON DATABASE postgres FROM guest_group;

GRANT EXECUTE ON FUNCTION read_messages TO guest_group;
GRANT EXECUTE ON FUNCTION send_messages TO guest_group;
GRANT EXECUTE ON FUNCTION activate_listener TO guest_group;

-- guest users
CREATE ROLE guest_1 PASSWORD 'guest_1' LOGIN;

REVOKE ALL PRIVILEGES ON SCHEMA public FROM guest_1;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM guest_1;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM guest_1;
REVOKE ALL PRIVILEGES ON DATABASE postgres FROM guest_1;

GRANT guest_group TO guest_1;
