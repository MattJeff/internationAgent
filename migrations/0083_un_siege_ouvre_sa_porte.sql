-- 0083_un_siege_ouvre_sa_porte: a seat receives strangers only once somebody
-- said yes.
--
-- `GET /book/{domain}/{slug}` is a page anyone on the internet can reach, and
-- what it does when a form comes back is put a message on an employee's thread
-- and an hour in its diary — two things that, until now, only a credential or a
-- signed webhook could do. One column decides whether that door exists for a
-- seat, and it is `false` on every row that already exists and every row to
-- come: the same reasoning as `max_turns_per_day = 0` — a seat does nothing
-- for nobody until an operator turns it on, and "nobody said no" is not the
-- same as "somebody said yes".
--
-- A column and not a table, because the fact has one bit and one reader.
-- `PUT /v1/employees/{id}/booking` flips it; the public page reads it with the
-- slug and the domain, and a closed seat and an absent one answer the same 404.
alter table employees
  add column if not exists booking_open boolean not null default false;
