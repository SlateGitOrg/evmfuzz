// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Token whose only minter/mover is the pool that created it.
contract PoolToken {
    address public immutable pool;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        pool = msg.sender;
    }

    modifier onlyPool() {
        require(msg.sender == pool, "pool");
        _;
    }

    function mint(address to, uint256 amount) external onlyPool {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function move(address from, address to, uint256 amount) external onlyPool {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @notice Constant-product pool over two tokens it deploys itself
///         (CREATE from a constructor; every swap is a cross-contract call).
/// @dev PLANTED BUG: `removeLiquidity` debits `amountA` from both reserves
///      (copy-paste slip). Harmless while the reserves are 1:1, so the
///      fuzzer must first move the price with a swap. Invariant broken:
///      reserveB == tokenB.balanceOf(pool).
contract Pool {
    PoolToken public immutable tokenA;
    PoolToken public immutable tokenB;
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => bool) public claimed;

    constructor() {
        tokenA = new PoolToken();
        tokenB = new PoolToken();
    }

    function faucet() external {
        require(!claimed[msg.sender], "claimed");
        claimed[msg.sender] = true;
        tokenA.mint(msg.sender, 1_000_000);
        tokenB.mint(msg.sender, 1_000_000);
    }

    function addLiquidity(uint256 amount) external {
        require(amount > 0, "zero");
        uint256 amountB = reserveA == 0 ? amount : (amount * reserveB) / reserveA;
        uint256 minted = totalShares == 0 ? amount : (amount * totalShares) / reserveA;
        require(minted > 0, "dust");
        tokenA.move(msg.sender, address(this), amount);
        tokenB.move(msg.sender, address(this), amountB);
        reserveA += amount;
        reserveB += amountB;
        totalShares += minted;
        shares[msg.sender] += minted;
    }

    function swap(bool aForB, uint256 amountIn) external returns (uint256 amountOut) {
        require(amountIn > 0 && reserveA > 0, "empty");
        (PoolToken tin, PoolToken tout, uint256 rin, uint256 rout) =
            aForB ? (tokenA, tokenB, reserveA, reserveB) : (tokenB, tokenA, reserveB, reserveA);
        uint256 inWithFee = amountIn * 997;
        amountOut = (inWithFee * rout) / (rin * 1000 + inWithFee);
        require(amountOut > 0, "dust");
        tin.move(msg.sender, address(this), amountIn);
        tout.move(address(this), msg.sender, amountOut);
        if (aForB) {
            reserveA += amountIn;
            reserveB -= amountOut;
        } else {
            reserveB += amountIn;
            reserveA -= amountOut;
        }
    }

    function removeLiquidity(uint256 shareAmount) external {
        require(shareAmount > 0 && shares[msg.sender] >= shareAmount, "shares");
        uint256 amountA = (shareAmount * reserveA) / totalShares;
        uint256 amountB = (shareAmount * reserveB) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        reserveA -= amountA;
        reserveB -= amountA; // BUG: should be amountB
        tokenA.move(address(this), msg.sender, amountA);
        tokenB.move(address(this), msg.sender, amountB);
    }
}
