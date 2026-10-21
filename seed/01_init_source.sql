-- Helper function to synthesize valid 12-digit Verhoeff test strings at DB init time
CREATE OR REPLACE FUNCTION pg_temp.synth_verhoeff_12(prefix11 TEXT) RETURNS TEXT AS $$
DECLARE
    d INT[] := ARRAY[
        [0,1,2,3,4,5,6,7,8,9], [1,2,3,4,0,6,7,8,9,5],
        [2,3,4,0,1,7,8,9,5,6], [3,4,0,1,2,8,9,5,6,7],
        [4,0,1,2,3,9,5,6,7,8], [5,9,8,7,6,0,4,3,2,1],
        [6,5,9,8,7,1,0,4,3,2], [7,6,5,9,8,2,1,0,4,3],
        [8,7,6,5,9,3,2,1,0,4], [9,8,7,6,5,4,3,2,1,0]
    ];
    p INT[] := ARRAY[
        [0,1,2,3,4,5,6,7,8,9], [1,5,7,6,2,8,3,0,9,4],
        [5,8,0,3,7,9,6,1,4,2], [8,9,1,6,0,4,3,5,2,7],
        [9,4,5,3,1,2,6,8,7,0], [4,2,8,6,5,7,3,9,0,1],
        [2,7,9,3,8,0,6,4,1,5], [7,0,4,6,9,1,3,2,5,8]
    ];
    inv INT[] := ARRAY[0,4,3,2,1,5,6,7,8,9];
    c INT := 0;
    i INT;
    digit INT;
BEGIN
    FOR i IN 1..11 LOOP
        digit := CAST(SUBSTRING(prefix11 FROM (12 - i) FOR 1) AS INT);
        c := d[c + 1][p[(i % 8) + 1][digit + 1] + 1];
    END LOOP;
    RETURN prefix11 || CAST(inv[c + 1] AS TEXT);
END;
$$ LANGUAGE plpgsql;

-- 1. CUSTOMERS TABLE
CREATE TABLE public.customers (
    customer_id SERIAL PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    email_address VARCHAR(150) NOT NULL,
    primary_mobile VARCHAR(20) NOT NULL,
    -- TRAP 1: Column named 'phone' that holds only NULLs or junk values
    phone VARCHAR(30),
    pan_card VARCHAR(15) NOT NULL,
    national_uid VARCHAR(20) NOT NULL,
    date_of_birth DATE NOT NULL,
    residential_address TEXT NOT NULL,
    pincode VARCHAR(10) NOT NULL,
    loyalty_tier VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO public.customers (
    full_name, email_address, primary_mobile, phone, pan_card,
    national_uid, date_of_birth, residential_address, pincode, loyalty_tier
) VALUES
('Aarav Sharma', 'aarav.sharma@gmail.com', '+91 9876543210', NULL, 'ABCPK1234F',
 pg_temp.synth_verhoeff_12('23456789012'), '1992-04-15', 'Flat 302, Green Glen Layout, Bellandur, Bengaluru, Karnataka', '560103', 'GOLD'),
('Priya Nair', 'priya.nair@outlook.in', '9845012345', 'N/A', 'BCFPN5678K',
 pg_temp.synth_verhoeff_12('34567890123'), '1988-11-23', 'House No 14, 2nd Cross, HSR Layout Sector 2, Bengaluru', '560102', 'PLATINUM'),
('Rohan Deshmukh', 'rohan.deshmukh@yahoo.co.in', '+91-9123456789', 'none', 'CDJPD9012M',
 pg_temp.synth_verhoeff_12('45678901234'), '1995-07-08', 'Plot 88, Baner Pashan Link Road, Near Savitribai Phule Chowk, Pune', '411045', 'SILVER'),
('Ananya Chatterjee', 'ananya.c@corporate.co.in', '09830054321', '0000000000', 'DEHPC3456R',
 pg_temp.synth_verhoeff_12('56789012345'), '1990-01-30', '12B Ballygunge Circular Road, Flat 4A, Kolkata, West Bengal', '700019', 'GOLD'),
('Vikramjit Singh', 'vikram.singh@rediffmail.com', '9811122334', NULL, 'EFGPS7890P',
 pg_temp.synth_verhoeff_12('67890123456'), '1985-09-12', 'B-42, Lajpat Nagar Part II, Ring Road, New Delhi', '110024', 'SILVER'),
('Sneha Iyer', 'sneha.iyer@techmail.in', '+91 9444055667', 'invalid', 'FGJPI2345L',
 pg_temp.synth_verhoeff_12('78901234567'), '1998-03-19', 'No 27, TTK Road, Alwarpet, Near Music Academy, Chennai', '600018', 'PLATINUM'),
('Karthik Reddy', 'karthik.reddy@startup.io', '9000111222', NULL, 'GHKPR6789Q',
 pg_temp.synth_verhoeff_12('89012345678'), '1993-12-05', 'Plot 401, Road No 36, Jubilee Hills, Hyderabad, Telangana', '500033', 'GOLD'),
('Meera Joshi', 'meera.joshi@domain.org.in', '+919820198201', '-', 'HJLPM4321Z',
 pg_temp.synth_verhoeff_12('90123456789'), '1991-06-25', '704 Sea Breeze Tower, Gokhale Road, Dadar West, Mumbai', '400028', 'SILVER');

-- 2. ORDERS TABLE
CREATE TABLE public.orders (
    order_id SERIAL PRIMARY KEY,
    customer_id INT REFERENCES public.customers(customer_id),
    -- TRAP 2: 6-digit and 12-digit numbers that are NOT pincodes or government IDs
    invoice_number INT NOT NULL,
    order_total_paise INT NOT NULL,
    order_status VARCHAR(32) NOT NULL,
    -- TRAP 3: Column named 'notes' that actually stores customer phone numbers
    notes VARCHAR(50),
    shipping_pincode VARCHAR(10) NOT NULL,
    ordered_at TIMESTAMP WITH TIME ZONE NOT NULL
);

INSERT INTO public.orders (
    customer_id, invoice_number, order_total_paise, order_status, notes, shipping_pincode, ordered_at
) VALUES
(1, 560109, 249900, 'DELIVERED', '+91 9876543210', '560103', '2026-09-10 14:22:00+05:30'),
(2, 411099, 159900, 'SHIPPED', '9845012345', '560102', '2026-09-12 09:15:00+05:30'),
(3, 700088, 89900, 'DELIVERED', '+91-9123456789', '411045', '2026-09-15 18:40:00+05:30'),
(4, 110077, 459900, 'PROCESSING', '9830054321', '700019', '2026-09-18 11:05:00+05:30'),
(5, 600066, 129900, 'DELIVERED', '9811122334', '110024', '2026-09-20 16:50:00+05:30'),
(6, 500055, 319900, 'CANCELLED', '+91 9444055667', '600018', '2026-09-22 20:10:00+05:30'),
(7, 400044, 199900, 'DELIVERED', '9000111222', '500033', '2026-09-25 13:30:00+05:30'),
(8, 831011, 99900, 'SHIPPED', '9820198201', '400028', '2026-09-28 08:45:00+05:30');

-- 3. SUPPORT TICKETS TABLE (with PII buried in free text)
CREATE TABLE public.support_tickets (
    ticket_id SERIAL PRIMARY KEY,
    customer_id INT REFERENCES public.customers(customer_id),
    category VARCHAR(50) NOT NULL,
    ticket_body TEXT NOT NULL,
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO public.support_tickets (customer_id, category, ticket_body, resolution_notes) VALUES
(1, 'REFUND_DELAY',
 'Hi support, my refund for invoice 560109 is still pending. Please call me urgently on +91 9876543210 or email aarav.sharma@gmail.com.',
 'Called customer and initiated NEFT refund.'),
(2, 'KYC_VERIFICATION',
 'Uploading my KYC details for high-value order: PAN is BCFPN5678K and UID is ' || pg_temp.synth_verhoeff_12('34567890123') || '. Please verify.',
 'KYC verified by compliance team.'),
(3, 'ADDRESS_CHANGE',
 'Please update delivery contact to 9123456789 and email rohan.deshmukh@yahoo.co.in before dispatch.',
 'Updated courier manifest.'),
(4, 'TAX_INVOICE',
 'Need GST/TDS update linked to PAN DEHPC3456R. You can reach me at ananya.c@corporate.co.in.',
 'Sent revised invoice PDF.'),
(5, 'GENERAL_INQUIRY',
 'When will the festive collection restock? Looking for silver anklets.',
 'Shared catalog restock date with user.'),
(6, 'PAYMENT_FAILURE',
 'Amount debited via UPI from 9444055667 but order failed. My email is sneha.iyer@techmail.in and PAN FGJPI2345L.',
 'Auto-refund confirmed within 48 hours.');