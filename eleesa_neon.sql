--
-- PostgreSQL database dump
--

\restrict BuPIzGYJfjerT7tPsipF9IxQFOMESsX3mMVzKLZnT54VBeZDkGpFUDJQvuhfz5f

-- Dumped from database version 18.7
-- Dumped by pg_dump version 18.7

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS '';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: courses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.courses (
    course_code character varying(15) NOT NULL,
    title character varying(150) NOT NULL,
    level integer NOT NULL,
    semester integer NOT NULL,
    credit_hours integer NOT NULL,
    prerequisites text,
    lecturer_id integer,
    CONSTRAINT courses_level_check CHECK ((level = ANY (ARRAY[100, 200, 300, 400]))),
    CONSTRAINT courses_semester_check CHECK ((semester = ANY (ARRAY[1, 2])))
);


--
-- Name: department_info; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.department_info (
    info_id integer NOT NULL,
    association_name character varying(150) NOT NULL,
    history text NOT NULL,
    vision text NOT NULL,
    mission text NOT NULL,
    hod_message text NOT NULL,
    president_message text NOT NULL,
    contact_email character varying(150),
    location_description text,
    office_hours character varying(100)
);


--
-- Name: department_info_info_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.department_info_info_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: department_info_info_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.department_info_info_id_seq OWNED BY public.department_info.info_id;


--
-- Name: labs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.labs (
    lab_id integer NOT NULL,
    lab_name character varying(120) NOT NULL,
    location character varying(100),
    safety_rules text NOT NULL
);


--
-- Name: labs_lab_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.labs_lab_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: labs_lab_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.labs_lab_id_seq OWNED BY public.labs.lab_id;


--
-- Name: notices_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notices_events (
    notice_id integer NOT NULL,
    title character varying(200) NOT NULL,
    body text NOT NULL,
    category character varying(40),
    posted_by integer,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    event_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT notices_events_approval_status_check CHECK (((approval_status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying])::text[]))),
    CONSTRAINT notices_events_category_check CHECK (((category)::text = ANY ((ARRAY['notice'::character varying, 'seminar'::character varying, 'workshop'::character varying, 'eleesa_event'::character varying, 'career_alumni'::character varying])::text[])))
);


--
-- Name: notices_events_notice_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.notices_events_notice_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notices_events_notice_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.notices_events_notice_id_seq OWNED BY public.notices_events.notice_id;


--
-- Name: resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resources (
    resource_id integer NOT NULL,
    course_code character varying(15),
    title character varying(200) NOT NULL,
    category character varying(40),
    file_or_external_url text NOT NULL,
    uploaded_by integer,
    approval_status character varying(20) DEFAULT 'pending'::character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT resources_approval_status_check CHECK (((approval_status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying])::text[]))),
    CONSTRAINT resources_category_check CHECK (((category)::text = ANY ((ARRAY['lecture_note'::character varying, 'past_question'::character varying, 'lab_manual'::character varying, 'formula_sheet'::character varying, 'datasheet'::character varying])::text[])))
);


--
-- Name: resources_resource_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.resources_resource_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: resources_resource_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.resources_resource_id_seq OWNED BY public.resources.resource_id;


--
-- Name: staff_directory; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.staff_directory (
    staff_id integer NOT NULL,
    user_id integer,
    full_name character varying(120) NOT NULL,
    rank character varying(80) NOT NULL,
    email character varying(150) NOT NULL,
    office_location character varying(100),
    research_interests text,
    consultation_hours character varying(120)
);


--
-- Name: staff_directory_staff_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.staff_directory_staff_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: staff_directory_staff_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.staff_directory_staff_id_seq OWNED BY public.staff_directory.staff_id;


--
-- Name: timetables; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.timetables (
    slot_id integer NOT NULL,
    course_code character varying(15),
    schedule_type character varying(20) NOT NULL,
    level integer NOT NULL,
    day_or_date character varying(30) NOT NULL,
    start_time time without time zone NOT NULL,
    end_time time without time zone NOT NULL,
    venue character varying(80) NOT NULL,
    CONSTRAINT timetables_schedule_type_check CHECK (((schedule_type)::text = ANY ((ARRAY['lecture'::character varying, 'exam'::character varying])::text[])))
);


--
-- Name: timetables_slot_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.timetables_slot_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: timetables_slot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.timetables_slot_id_seq OWNED BY public.timetables.slot_id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    user_id integer NOT NULL,
    index_or_staff_id character varying(30) NOT NULL,
    full_name character varying(120) NOT NULL,
    email character varying(150) NOT NULL,
    password_hash text NOT NULL,
    role character varying(20) NOT NULL,
    level integer,
    is_active boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT users_level_check CHECK ((level = ANY (ARRAY[100, 200, 300, 400]))),
    CONSTRAINT users_role_check CHECK (((role)::text = ANY ((ARRAY['student'::character varying, 'executive'::character varying, 'lecturer'::character varying, 'hod_admin'::character varying])::text[])))
);


--
-- Name: users_user_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;


--
-- Name: department_info info_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.department_info ALTER COLUMN info_id SET DEFAULT nextval('public.department_info_info_id_seq'::regclass);


--
-- Name: labs lab_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.labs ALTER COLUMN lab_id SET DEFAULT nextval('public.labs_lab_id_seq'::regclass);


--
-- Name: notices_events notice_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notices_events ALTER COLUMN notice_id SET DEFAULT nextval('public.notices_events_notice_id_seq'::regclass);


--
-- Name: resources resource_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources ALTER COLUMN resource_id SET DEFAULT nextval('public.resources_resource_id_seq'::regclass);


--
-- Name: staff_directory staff_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.staff_directory ALTER COLUMN staff_id SET DEFAULT nextval('public.staff_directory_staff_id_seq'::regclass);


--
-- Name: timetables slot_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.timetables ALTER COLUMN slot_id SET DEFAULT nextval('public.timetables_slot_id_seq'::regclass);


--
-- Name: users user_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);


--
-- Data for Name: courses; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.courses (course_code, title, level, semester, credit_hours, prerequisites, lecturer_id) FROM stdin;
EE 151	Applied Electricity	100	1	3	None	1
EE 253	Digital Electronics & Logic Design	200	1	3	EE 151	2
EE 355	AC Machinery & Transformers	300	1	3	EE 252	2
EE 361	Power System Analysis	300	1	3	EE 254	1
EE 451	High Voltage Engineering & Protection	400	1	3	EE 361	1
\.


--
-- Data for Name: department_info; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.department_info (info_id, association_name, history, vision, mission, hod_message, president_message, contact_email, location_description, office_hours) FROM stdin;
1	ELEESA — Electrical and Electronic Engineering Students' Association	Founded to unite engineering students, bridge classroom theory with industry practice, and support academic excellence.	To nurture innovative, ethical, and industry-ready Electrical and Electronic Engineers.	Empowering students through technical workshops, mentorship, lab access, and peer collaboration.	Welcome to the official ELEESA and Department Digital Portal.	Together we innovate, build, and power the future. Welcome to ELEESA!	eleesa.secretariat@university.edu.gh	Engineering Block B, Ground Floor Secretariat	Mon - Fri, 8:00 AM - 5:00 PM
\.


--
-- Data for Name: labs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.labs (lab_id, lab_name, location, safety_rules) FROM stdin;
1	Electrical Machines & Drives Lab	Block A, Ground Floor	Wear insulated safety boots. Never energize synchronous/induction rigs before supervisor inspection.
2	Power Systems & High Voltage Lab	High Voltage Annex	Maintain minimum clearance from HV busbars. Two-person rule required at all times.
3	Embedded Systems & Electronics Lab	Block B, Room 102	Verify DC power supply current limits before powering microcontroller boards.
\.


--
-- Data for Name: notices_events; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.notices_events (notice_id, title, body, category, posted_by, approval_status, event_date) FROM stdin;
1	ELEESA Primary Substation Technical Tour	Level 300 and 400 members are invited to register at the ELEESA secretariat for the substation visit.	eleesa_event	3	approved	2026-11-28 09:00:00
2	Mid-Semester Lab Logbook Submission	All AC Machinery and Power Systems lab logbooks must be submitted by Friday 4:00 PM.	notice	2	approved	2026-11-21 16:00:00
\.


--
-- Data for Name: resources; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.resources (resource_id, course_code, title, category, file_or_external_url, uploaded_by, approval_status, created_at) FROM stdin;
1	EE 355	Synchronous & Induction Machines Notes	lecture_note	https://example.edu/ee355_notes.pdf	2	approved	2026-11-17 09:40:19.994441
2	EE 361	Per-Unit & Load Flow Formula Sheet	formula_sheet	https://example.edu/ee361_formulas.pdf	1	approved	2026-11-17 09:40:19.994441
\.


--
-- Data for Name: staff_directory; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.staff_directory (staff_id, user_id, full_name, rank, email, office_location, research_interests, consultation_hours) FROM stdin;
1	1	Prof. K. Boateng	Associate Professor	k.boateng@eleesa.edu	Block B, Room 204	Power Systems & High Voltage	Tuesdays 10:00 AM - 1:00 PM
2	2	Dr. A. Mensah	Senior Lecturer	a.mensah@eleesa.edu	Block B, Room 108	AC Machines & Control Drives	Thursdays 1:00 PM - 4:00 PM
\.


--
-- Data for Name: timetables; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.timetables (slot_id, course_code, schedule_type, level, day_or_date, start_time, end_time, venue) FROM stdin;
1	EE 355	lecture	300	Monday	08:00:00	10:00:00	Engineering Auditorium B
2	EE 361	lecture	300	Wednesday	10:30:00	12:30:00	Block B, Room 201
3	EE 253	lecture	200	Thursday	13:00:00	15:00:00	Electronics Lab Annex
4	EE 355	exam	300	2026-12-14	09:00:00	12:00:00	Main Examination Hall
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.users (user_id, index_or_staff_id, full_name, email, password_hash, role, level, is_active, created_at) FROM stdin;
1	STF-001	Prof. K. Boateng	k.boateng@eleesa.edu	hashed_pw_1	lecturer	\N	t	2026-11-17 09:40:19.994441
2	STF-002	Dr. A. Mensah	a.mensah@eleesa.edu	hashed_pw_2	lecturer	\N	t	2026-11-17 09:40:19.994441
3	ELE/300/030	Maxwell Amoah	m.amoah@student.edu	hashed_pw_3	executive	300	t	2026-11-17 09:40:19.994441
\.


--
-- Name: department_info_info_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.department_info_info_id_seq', 1, true);


--
-- Name: labs_lab_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.labs_lab_id_seq', 3, true);


--
-- Name: notices_events_notice_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.notices_events_notice_id_seq', 2, true);


--
-- Name: resources_resource_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.resources_resource_id_seq', 2, true);


--
-- Name: staff_directory_staff_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.staff_directory_staff_id_seq', 2, true);


--
-- Name: timetables_slot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.timetables_slot_id_seq', 4, true);


--
-- Name: users_user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.users_user_id_seq', 3, true);


--
-- Name: courses courses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.courses
    ADD CONSTRAINT courses_pkey PRIMARY KEY (course_code);


--
-- Name: department_info department_info_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.department_info
    ADD CONSTRAINT department_info_pkey PRIMARY KEY (info_id);


--
-- Name: labs labs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.labs
    ADD CONSTRAINT labs_pkey PRIMARY KEY (lab_id);


--
-- Name: notices_events notices_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notices_events
    ADD CONSTRAINT notices_events_pkey PRIMARY KEY (notice_id);


--
-- Name: resources resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_pkey PRIMARY KEY (resource_id);


--
-- Name: staff_directory staff_directory_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.staff_directory
    ADD CONSTRAINT staff_directory_pkey PRIMARY KEY (staff_id);


--
-- Name: timetables timetables_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.timetables
    ADD CONSTRAINT timetables_pkey PRIMARY KEY (slot_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_index_or_staff_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_index_or_staff_id_key UNIQUE (index_or_staff_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: courses courses_lecturer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.courses
    ADD CONSTRAINT courses_lecturer_id_fkey FOREIGN KEY (lecturer_id) REFERENCES public.staff_directory(staff_id) ON DELETE SET NULL;


--
-- Name: notices_events notices_events_posted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notices_events
    ADD CONSTRAINT notices_events_posted_by_fkey FOREIGN KEY (posted_by) REFERENCES public.users(user_id);


--
-- Name: resources resources_course_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_course_code_fkey FOREIGN KEY (course_code) REFERENCES public.courses(course_code) ON DELETE SET NULL;


--
-- Name: resources resources_uploaded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_uploaded_by_fkey FOREIGN KEY (uploaded_by) REFERENCES public.users(user_id);


--
-- Name: staff_directory staff_directory_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.staff_directory
    ADD CONSTRAINT staff_directory_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE SET NULL;


--
-- Name: timetables timetables_course_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.timetables
    ADD CONSTRAINT timetables_course_code_fkey FOREIGN KEY (course_code) REFERENCES public.courses(course_code) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict BuPIzGYJfjerT7tPsipF9IxQFOMESsX3mMVzKLZnT54VBeZDkGpFUDJQvuhfz5f

