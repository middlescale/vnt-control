DO $$
DECLARE
	current_pk TEXT[];
BEGIN
	SELECT ARRAY_AGG(att.attname ORDER BY att.attnum)
	  INTO current_pk
	  FROM pg_constraint con
	  JOIN pg_class rel ON rel.oid = con.conrelid
	  JOIN unnest(con.conkey) WITH ORDINALITY AS cols(attnum, ord) ON TRUE
	  JOIN pg_attribute att ON att.attrelid = rel.oid AND att.attnum = cols.attnum
	 WHERE rel.relname = 'um_certified_devices'
	   AND con.contype = 'p';
	IF current_pk = ARRAY['device_id'] THEN
		ALTER TABLE um_certified_devices DROP CONSTRAINT IF EXISTS um_certified_devices_pkey;
		ALTER TABLE um_certified_devices ADD CONSTRAINT um_certified_devices_pkey PRIMARY KEY (group_name, device_id);
	END IF;
END
$$;
