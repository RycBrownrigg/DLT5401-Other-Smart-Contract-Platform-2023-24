use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use anchor_spl::associated_token::AssociatedToken;

// Declare the program ID for the program
declare_id!("PROGRAM_ID");

#[program]
pub mod safe_trading_zone {
    use super::*;

    // Initialize a new trade
    pub fn initialize_trade(
        ctx: Context<InitializeTrade>,
        trade_id: u64,
        amount: u64,
        notary: Pubkey,
    ) -> Result<()> {
        let trade_escrow = &mut ctx.accounts.trade_escrow;
        
        // Set up the trade escrow account
        trade_escrow.trade_id = trade_id;
        trade_escrow.buyer = ctx.accounts.buyer.key();
        trade_escrow.seller = ctx.accounts.seller.key();
        trade_escrow.notary = notary;
        trade_escrow.amount = amount;
        trade_escrow.buyer_confirmed = false;
        trade_escrow.notary_confirmed = false;
        trade_escrow.bump = *ctx.bumps.get("trade_escrow").unwrap();

        // Transfer funds from buyer to escrow
        ctx.accounts.transfer_to_escrow(amount)?;

        msg!("Trade initialized: {}", trade_id);
        Ok(())
    }

    // Confirm inspection by buyer or notary
    pub fn confirm_inspection(
        ctx: Context<ConfirmInspection>,
        trade_id: u64,
    ) -> Result<()> {
        let trade_escrow = &mut ctx.accounts.trade_escrow;

        // Ensure the trade ID matches
        require_keys_eq!(
            trade_escrow.trade_id,
            trade_id,
            ErrorCode::InvalidTradeId
        );

        // Check if the signer is the buyer or notary and update confirmation status
        if ctx.accounts.signer.key() == trade_escrow.buyer {
            require!(!trade_escrow.buyer_confirmed, ErrorCode::AlreadyConfirmed);
            trade_escrow.buyer_confirmed = true;
            msg!("Buyer confirmed inspection for trade: {}", trade_id);
        } else if ctx.accounts.signer.key() == trade_escrow.notary {
            require!(!trade_escrow.notary_confirmed, ErrorCode::AlreadyConfirmed);
            trade_escrow.notary_confirmed = true;
            msg!("Notary confirmed inspection for trade: {}", trade_id);
        } else {
            return Err(ErrorCode::Unauthorized.into());
        }

        Ok(())
    }

    // Complete the trade and distribute funds
    pub fn complete_trade(ctx: Context<CompleteTrade>, trade_id: u64) -> Result<()> {
        let trade_escrow = &ctx.accounts.trade_escrow;

        // Ensure the trade ID matches
        require_keys_eq!(
            trade_escrow.trade_id,
            trade_id,
            ErrorCode::InvalidTradeId
        );

        // Check if both buyer and notary have confirmed
        require!(
            trade_escrow.buyer_confirmed && trade_escrow.notary_confirmed,
            ErrorCode::TradeNotFullyConfirmed
        );

        // Calculate amounts for seller and safe zone
        let seller_amount = trade_escrow.amount * 95 / 100;
        let safe_zone_amount = trade_escrow.amount - seller_amount;

        // Transfer funds to seller
        ctx.accounts.transfer_to_seller(seller_amount)?;

        // Transfer funds to safe zone
        ctx.accounts.transfer_to_safe_zone(safe_zone_amount)?;

        msg!("Trade completed: {}", trade_id);
        Ok(())
    }
}

// Account structure for initializing a trade
#[derive(Accounts)]
#[instruction(trade_id: u64, amount: u64)]
pub struct InitializeTrade<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,
    pub seller: AccountInfo<'info>,
    pub mint: Account<'info, token::Mint>,
    #[account(
        init,
        payer = buyer,
        space = TradeEscrow::LEN,
        seeds = [b"trade_escrow", trade_id.to_le_bytes().as_ref()],
        bump
    )]
    pub trade_escrow: Account<'info, TradeEscrow>,
    #[account(
        init,
        payer = buyer,
        associated_token::mint = mint,
        associated_token::authority = trade_escrow
    )]
    pub escrow_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = buyer
    )]
    pub buyer_token_account: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub rent: Sysvar<'info, Rent>,
}

// Account structure for confirming inspection
#[derive(Accounts)]
#[instruction(trade_id: u64)]
pub struct ConfirmInspection<'info> {
    pub signer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"trade_escrow", trade_id.to_le_bytes().as_ref()],
        bump = trade_escrow.bump
    )]
    pub trade_escrow: Account<'info, TradeEscrow>,
}

// Account structure for completing a trade
#[derive(Accounts)]
#[instruction(trade_id: u64)]
pub struct CompleteTrade<'info> {
    #[account(mut)]
    pub seller: Signer<'info>,
    #[account(mut)]
    pub safe_zone: AccountInfo<'info>,
    #[account(
        mut,
        seeds = [b"trade_escrow", trade_id.to_le_bytes().as_ref()],
        bump = trade_escrow.bump,
        close = seller
    )]
    pub trade_escrow: Account<'info, TradeEscrow>,
    #[account(mut)]
    pub escrow_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = escrow_token_account.mint,
        associated_token::authority = seller
    )]
    pub seller_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = escrow_token_account.mint,
        associated_token::authority = safe_zone
    )]
    pub safe_zone_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

// Trade escrow account structure
#[account]
pub struct TradeEscrow {
    pub trade_id: u64,
    pub buyer: Pubkey,
    pub seller: Pubkey,
    pub notary: Pubkey,
    pub amount: u64,
    pub buyer_confirmed: bool,
    pub notary_confirmed: bool,
    pub bump: u8,
}

impl TradeEscrow {
    // Calculate the size of the TradeEscrow account
    pub const LEN: usize = 8 + 8 + 32 + 32 + 32 + 8 + 1 + 1 + 1;
}

// Error codes for the program
#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Trade already confirmed")]
    AlreadyConfirmed,
    #[msg("Trade not fully confirmed")]
    TradeNotFullyConfirmed,
    #[msg("Invalid trade ID")]
    InvalidTradeId,
}

// Helper methods for InitializeTrade
impl<'info> InitializeTrade<'info> {
    // Transfer tokens from buyer to escrow account
    pub fn transfer_to_escrow(&self, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
            from: self.buyer_token_account.to_account_info(),
            to: self.escrow_token_account.to_account_info(),
            authority: self.buyer.to_account_info(),
        };
        let cpi_program = self.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)
    }
}

// Helper methods for CompleteTrade
impl<'info> CompleteTrade<'info> {
    // Transfer tokens from escrow to seller
    pub fn transfer_to_seller(&self, amount: u64) -> Result<()> {
        let seeds = &[
            b"trade_escrow",
            &self.trade_escrow.trade_id.to_le_bytes(),
            &[self.trade_escrow.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: self.escrow_token_account.to_account_info(),
            to: self.seller_token_account.to_account_info(),
            authority: self.trade_escrow.to_account_info(),
        };
        let cpi_program = self.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        token::transfer(cpi_ctx, amount)
    }

    // Transfer tokens from escrow to safe zone
    pub fn transfer_to_safe_zone(&self, amount: u64) -> Result<()> {
        let seeds = &[
            b"trade_escrow",
            &self.trade_escrow.trade_id.to_le_bytes(),
            &[self.trade_escrow.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: self.escrow_token_account.to_account_info(),
            to: self.safe_zone_token_account.to_account_info(),
            authority: self.trade_escrow.to_account_info(),
        };
        let cpi_program = self.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        token::transfer(cpi_ctx, amount)
    }
}