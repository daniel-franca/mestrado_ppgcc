# Based on https://plotly.com/python/radar-chart/ - 2025-03-06

import plotly.graph_objects as go

categories = ['2023','2022','2021', '2020', '2019']

# Debian
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[482.14, 679.97, 875.97, 1170.88, 1441.47],
      theta=categories,
      name='Trixie'
))
fig.add_trace(go.Scatterpolar(
      r=[434.14, 666.45, 898.19, 1197.71, 1467.40],
      theta=categories,
      name='Sid',
))
fig.add_trace(go.Scatterpolar(
      r=[379.52, 540.14, 629.95, 842.02, 1089.09],
      theta=categories,
      name='Bullseye'
))
fig.add_trace(go.Scatterpolar(
      r=[448.18, 586.08, 775.70, 1065.60, 1337.48],
      theta=categories,
      name='Bookworm',
))

fig.update_layout(
    title="Debian",
    legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(
                size=20
            )
        ),
    polar=dict(
        angularaxis_tickfont_size=20,
        radialaxis=dict(
            visible=True,
            tickfont=dict(size=18),
            range=[0, 1500],
    )),

showlegend = True,
)

line_close=True
fig.show()

# Ubuntu
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[775.52, 817.65, 962.17, 213.27, 316.32],
      theta=categories,
      name='16.04'
))
fig.add_trace(go.Scatterpolar(
      r=[468.91, 378.96, 347.14, 168.43, 743.12],
      theta=categories,
      name='22.04'
))
fig.add_trace(go.Scatterpolar(
      r=[449.08, 352.47, 305.09, 234.76, 714.46],
      theta=categories,
      name='20.04'
))
fig.add_trace(go.Scatterpolar(
      r=[634.03, 393.46, 255.34, 156.62, 216.86],
      theta=categories,
      name='18.04'
))

fig.update_layout(
    title="Ubuntu",
    legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(
                size=20
            )
        ),
    polar=dict(
        angularaxis_tickfont_size=20,
        radialaxis=dict(
            visible=True,
            tickfont=dict(size=18),
            range=[0, 1000],
    )),

showlegend = True,
)

line_close=True
fig.show()

# Ubuntu Pro
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[775.87, 729.47, 750.06, 194.36, 297.43],
      theta=categories,
      name='16.04'
))
fig.add_trace(go.Scatterpolar(
      r=[469.46, 377.68, 346.30, 168.43, 743.12],
      theta=categories,
      name='22.04'
))
fig.add_trace(go.Scatterpolar(
      r=[448.33, 351.35, 295.70, 230.60, 709.59],
      theta=categories,
      name='20.04'
))
fig.add_trace(go.Scatterpolar(
      r=[665.29, 392.18, 248.24, 153.62, 213.99],
      theta=categories,
      name='18.04'
))

fig.update_layout(
    title="Ubuntu Pro",
    legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(
                size=20
            )
        ),
    polar=dict(
        angularaxis_tickfont_size=20,
        radialaxis=dict(
            visible=True,
            tickfont=dict(size=18),
            range=[0, 800],
    )),

showlegend = True,
)

line_close=True
fig.show()

# ALmaLinux
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[418.25, 394.81, 381.00, 509.39, 655.99],
      theta=categories,
      name='8'
))
fig.add_trace(go.Scatterpolar(
      r=[405.76, 386.18, 393.53, 508.36, 535.44],
      theta=categories,
      name='9',
))

fig.update_layout(
    title="AlmaLinux",
    legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(
                size=20
            )
        ),
    polar=dict(
        angularaxis_tickfont_size=20,
        radialaxis=dict(
            visible=True,
            tickfont=dict(size=18),
            range=[0, 700],
    )),

showlegend = True,
)

line_close=True
fig.show()

# Rocky Linux
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[432.11, 360.00, 315.86, 373.27, 444.17],
      theta=categories,
      name='8'
))
fig.add_trace(go.Scatterpolar(
      r=[410.98, 347.52, 328.93, 369.92, 296.30],
      theta=categories,
      name='9',
))

fig.update_layout(
    title="Rocky Linux",
    legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(
                size=20
            )
        ),
    polar=dict(
        angularaxis_tickfont_size=20,
        radialaxis=dict(
            visible=True,
            tickfont=dict(size=18),
            range=[0, 500],
    )),

showlegend = True,
)

line_close=True
fig.show()

# Red Hat
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[449.80, 439.80, 425.74, 353.65, 382.67],
      theta=categories,
      name='6'
))
fig.add_trace(go.Scatterpolar(
      r=[459.99, 459.09, 424.66, 229.43, 224.51],
      theta=categories,
      name='7',
))
fig.add_trace(go.Scatterpolar(
      r=[420.80, 349.45, 256.51, 193.30, 235.18],
      theta=categories,
      name='8'
))
fig.add_trace(go.Scatterpolar(
      r=[412.34, 342.94, 263.64, 193.87, 208.38],
      theta=categories,
      name='9',
))

fig.update_layout(
    title="Red Hat",
    legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(
                size=20
            )
        ),
    polar=dict(
        angularaxis_tickfont_size=20,
        radialaxis=dict(
            visible=True,
            tickfont=dict(size=18),
            range=[0, 500],
    )),

showlegend = True,
)

line_close=True
fig.show()
