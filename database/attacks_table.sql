-- Create attacks table for logging security attacks
CREATE TABLE IF NOT EXISTS attacks (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    attacker_ip VARCHAR(50) NOT NULL,
    attacker_email VARCHAR(255),
    stolen_data TEXT,
    target_url TEXT,
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'mitigated')),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    mitigated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_attacks_status ON attacks(status);
CREATE INDEX IF NOT EXISTS idx_attacks_attacker_email ON attacks(attacker_email);
CREATE INDEX IF NOT EXISTS idx_attacks_detected_at ON attacks(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_attacks_attack_type ON attacks(attack_type);

-- Add RLS (Row Level Security) policies
ALTER TABLE attacks ENABLE ROW LEVEL SECURITY;

-- Allow security_team, admin, and owner to view all attacks
CREATE POLICY "Security team can view attacks" ON attacks
    FOR SELECT
    USING (
        auth.jwt() ->> 'role' IN ('security_team', 'admin', 'owner')
    );

-- Allow system to insert attacks (no auth required for logging)
CREATE POLICY "System can insert attacks" ON attacks
    FOR INSERT
    TO public
    WITH CHECK (true);

-- Only security_team and above can update attacks
CREATE POLICY "Security team can update attacks" ON attacks
    FOR UPDATE
    USING (
        auth.jwt() ->> 'role' IN ('security_team', 'admin', 'owner')
    );

-- Update users table to add blocked_at field if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'blocked_at'
    ) THEN
        ALTER TABLE users ADD COLUMN blocked_at TIMESTAMP WITH TIME ZONE;
    END IF;
END $$;

-- Add status column to users if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'status'
    ) THEN
        ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'blocked'));
    END IF;
END $$;
