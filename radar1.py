# Based on https://plotly.com/python/radar-chart/ - 2025-03-06

import plotly.graph_objects as go

categories = ['2023','2022','2021', '2020', '2019']

# ALmaLinux
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[418.25, 394.81, 381.00, 509.39, 655.99],
      theta=categories,
      name='AlmaLinux 8'
))
fig.add_trace(go.Scatterpolar(
      r=[405.76, 386.18, 393.53, 508.36, 535.44],
      theta=categories,
      name='AlmaLinux 9',
))

fig.update_layout(
  polar=dict(
    angularaxis_tickfont_size=20,
    radialaxis=dict(
      visible=False,
      range=[0, 700],
    ))
    ,
  showlegend=True,
  legend=dict(yanchor="top", y=0.9, xanchor="left", x=0.4, font=dict(size=12),)
)

line_close=True

fig.show()

# Rocky Linux

fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[432.11, 360.00, 315.86, 373.27, 444.17],
      theta=categories,
      name='Rocky Linux 8'
))
fig.add_trace(go.Scatterpolar(
      r=[410.98, 347.52, 328.93, 369.92, 296.30],
      theta=categories,
      name='Rocky Linux 9',
))

fig.update_layout(
  polar=dict(
    angularaxis_tickfont_size=20,
    radialaxis=dict(
      visible=False,
      range=[0, 700],
    ))
    ,
  showlegend=True,
  legend=dict(yanchor="top", y=0.9, xanchor="left", x=0.4, font=dict(size=12),)
)

line_close=True

fig.show()

# Red Hat

fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=[449.80, 439.80, 425.74, 353.65, 382.67],
      theta=categories,
      name='Red Hat 6'
))
fig.add_trace(go.Scatterpolar(
      r=[459.99, 459.09, 424.66, 229.43, 224.51],
      theta=categories,
      name='Red Hat 7',
))
fig.add_trace(go.Scatterpolar(
      r=[420.80, 349.45, 256.51, 193.30, 235.18],
      theta=categories,
      name='Red Hat 8'
))
fig.add_trace(go.Scatterpolar(
      r=[412.34, 342.94, 263.64, 193.87, 208.38],
      theta=categories,
      name='Red Hat 9',
))

fig.update_layout(
  polar=dict(
    angularaxis_tickfont_size=20,
    radialaxis=dict(
      visible=False,
      range=[0, 500],
    ))
    ,
  showlegend=True,
  legend=dict(yanchor="bottom", y=-0.1, xanchor="left", x=0.4, font=dict(size=12),)
)

line_close=True

fig.show()
