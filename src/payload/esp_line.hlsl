// Minimal line-list shaders for ESP overlay (Phase 05b-iii, DXGI Present hook).
// Positions in clip space (computed CPU-side via W2S), flat vertex color.
struct VSIn
{
    float4 pos : POSITION;
    float4 col : COLOR;
};
struct PSIn
{
    float4 pos : SV_POSITION;
    float4 col : COLOR;
};
PSIn VSMain(VSIn i)
{
    PSIn o;
    o.pos = i.pos;
    o.col = i.col;
    return o;
}
float4 PSMain(PSIn i) : SV_Target
{
    return i.col;
}
