# Based on https://plotly.com/python/radar-chart/ - 2025-03-06

import plotly.graph_objects as go

categories = ['2023','2022','2021', '2020', '2019']

# Debian
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[482.14, 679.97, 875.97, 1170.88, 1441.47],
      theta=categories,
      name='Debian Trixie'
))
fig.add_trace(go.Scatterpolar(
      r=[434.14, 666.45, 898.19, 1197.71, 1467.40],
      theta=categories,
      name='Debian Sid',
))
fig.add_trace(go.Scatterpolar(
      r=[379.52, 540.14, 629.95, 842.02, 1089.09],
      theta=categories,
      name='Debian Bullseye'
))
fig.add_trace(go.Scatterpolar(
      r=[448.18, 586.08, 775.70, 1065.60, 1337.48],
      theta=categories,
      name='Debian Bookworm',
))

fig.update_layout(
  polar=dict(
    angularaxis_tickfont_size=20,
    radialaxis=dict(
      visible=False,
      range=[0, 1500],
    ))
    ,
  showlegend=True,
  legend=dict(yanchor="top", y=0.9, xanchor="left", x=0.4, font=dict(size=12),)
)

line_close=True

fig.show()

# Ubuntu And Ubuntu Pro
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[775.52, 817.65, 962.17, 213.27, 316.32],
      theta=categories,
      name='Ubuntu Xenial'
))
fig.add_trace(go.Scatterpolar(
      r=[468.91, 378.96, 347.14, 168.43, 743.12],
      theta=categories,
      name='Ubuntu Jammy'
))
fig.add_trace(go.Scatterpolar(
      r=[449.08, 352.47, 305.09, 234.76, 714.46],
      theta=categories,
      name='Ubuntu Focal'
))
fig.add_trace(go.Scatterpolar(
      r=[634.03, 393.46, 255.34, 156.62, 216.86],
      theta=categories,
      name='Ubuntu Bionic'
))
fig.add_trace(go.Scatterpolar(
      r=[775.87, 729.47, 750.06, 194.36, 297.43],
      theta=categories,
      name='Ubuntu Pro Xenial'
))
fig.add_trace(go.Scatterpolar(
      r=[469.46, 377.68, 346.30, 168.43, 743.12],
      theta=categories,
      name='Ubuntu Pro Jammy'
))
fig.add_trace(go.Scatterpolar(
      r=[448.33, 351.35, 295.70, 230.60, 709.59],
      theta=categories,
      name='Ubuntu Pro Focal'
))
fig.add_trace(go.Scatterpolar(
      r=[665.29, 392.18, 248.24, 153.62, 213.99],
      theta=categories,
      name='Ubuntu Pro Bionic'
))

fig.update_layout(
  polar=dict(
    angularaxis_tickfont_size=20,
    radialaxis=dict(
      visible=False,
      range=[0, 1200],
    ))
    ,
  showlegend=True,
  legend=dict(yanchor="bottom", y=-0.1, xanchor="left", x=0.4, font=dict(size=12),)
)

line_close=True

fig.show()
